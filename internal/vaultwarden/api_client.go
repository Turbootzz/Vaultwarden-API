package vaultwarden

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
	"github.com/google/uuid"
)

// PreloginResponse contains the KDF parameters from the server.
type PreloginResponse struct {
	KDF            int  `json:"kdf"`
	KDFIterations  int  `json:"kdfIterations"`
	KDFMemory      *int `json:"kdfMemory"`
	KDFParallelism *int `json:"kdfParallelism"`
}

// TokenResponse is returned by the /identity/connect/token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
	PrivateKey   string `json:"PrivateKey"`
}

// SyncResponse contains the full vault sync data.
type SyncResponse struct {
	Profile     SyncProfile      `json:"profile"`
	Ciphers     []SyncCipher     `json:"ciphers"`
	Collections []SyncCollection `json:"collections"`
	Folders     []SyncFolder     `json:"folders"`
}

// SyncProfile contains user profile info.
type SyncProfile struct {
	ID            string             `json:"id"`
	Email         string             `json:"email"`
	Key           string             `json:"key"`
	PrivateKey    string             `json:"privateKey"`
	Organizations []SyncOrganization `json:"organizations"`
}

// SyncOrganization represents an organization the user belongs to.
type SyncOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// SyncCollection represents a collection that logins can be assigned to.
type SyncCollection struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
}

// SyncFolder represents a folder that logins can be assigned to.
type SyncFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SyncCipher represents an encrypted vault item from the sync response.
type SyncCipher struct {
	ID             string      `json:"id"`
	Type           int         `json:"type"`
	OrganizationID *string     `json:"organizationId"`
	CollectionIDs  []string    `json:"collectionIds"`
	FolderID       *string     `json:"folderId"`
	Name           string      `json:"name"`
	DeletedDate    *string     `json:"deletedDate"`
	Notes          *string     `json:"notes"`
	Login          *SyncLogin  `json:"login"`
	Card           *SyncCard   `json:"card"`
	Fields         []SyncField `json:"fields"`
}

// SyncLogin contains encrypted login data.
type SyncLogin struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	URI      *string `json:"uri"`
	URIs     []struct {
		URI *string `json:"uri"`
	} `json:"uris"`
}

// SyncCard contains encrypted card data.
type SyncCard struct {
	CardholderName *string `json:"cardholderName"`
	Number         *string `json:"number"`
	Code           *string `json:"code"`
}

// SyncField contains encrypted custom field data.
type SyncField struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
	Type  int     `json:"type"`
}

// Bitwarden cipher types.
const (
	CipherTypeLogin      = 1
	CipherTypeSecureNote = 2
	CipherTypeCard       = 3
	CipherTypeIdentity   = 4
)

// APIClient communicates directly with the Vaultwarden HTTP API.
type APIClient struct {
	baseURL      string
	email        string
	password     string
	clientID     string // Optional: for API key login (bypasses 2FA)
	clientSecret string // Optional: for API key login (bypasses 2FA)
	httpClient   *http.Client
	deviceID     string

	// renewMu serializes credential renewal. Lock order: renewMu before mu, never the reverse.
	renewMu sync.Mutex

	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	tokenExpiry  time.Time
	symKey       SymmetricKey
}

// NewAPIClient creates a new Vaultwarden API client.
// clientID and clientSecret are optional — if provided, API key login is used (bypasses 2FA).
func NewAPIClient(baseURL, email, password, clientID, clientSecret string) *APIClient {
	return &APIClient{
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		email:        email,
		password:     password,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		deviceID: uuid.New().String(),
	}
}

// Authenticate performs the full login flow.
// If API key credentials are set, uses client_credentials grant (bypasses 2FA).
// Otherwise, uses password grant (requires 2FA to be disabled or handled).
func (ac *APIClient) Authenticate() error {
	// Step 1: Get KDF parameters.
	prelogin, err := ac.prelogin()
	if err != nil {
		return fmt.Errorf("prelogin: %w", err)
	}

	logger.Info.Printf("KDF type: %d, iterations: %d", prelogin.KDF, prelogin.KDFIterations)

	// Step 2: Derive master key (always needed for decryption).
	masterKey, err := MakeMasterKey(ac.password, ac.email, prelogin.KDF, prelogin.KDFIterations, prelogin.KDFMemory, prelogin.KDFParallelism)
	if err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}

	// Step 3: Login.
	var tokenResp *TokenResponse
	if ac.clientID != "" && ac.clientSecret != "" {
		// API key login — bypasses 2FA.
		logger.Info.Println("Using API key authentication (2FA bypass)")
		tokenResp, err = ac.loginWithAPIKey()
	} else {
		// Password login — requires no 2FA or 2FA handling.
		hashedPassword := HashPassword(ac.password, masterKey)
		tokenResp, err = ac.loginWithPassword(hashedPassword)
	}
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	// Step 4: Get the encrypted symmetric key.
	// API key login doesn't return the Key in the token response,
	// so we get it from the sync/profile endpoint.
	encryptedKey := tokenResp.Key
	if encryptedKey == "" {
		encryptedKey, err = ac.fetchProfileKey(tokenResp.AccessToken)
		if err != nil {
			return fmt.Errorf("fetch profile key: %w", err)
		}
	}

	// Step 5: Decrypt the symmetric key.
	symKey, err := DecryptSymmetricKey(encryptedKey, masterKey)
	if err != nil {
		return fmt.Errorf("decrypt symmetric key: %w", err)
	}

	// Step 6: Publish tokens and key under one lock so no reader pairs a new token with the old key.
	ac.mu.Lock()
	ac.accessToken = tokenResp.AccessToken
	ac.refreshToken = tokenResp.RefreshToken
	ac.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	ac.symKey = symKey
	ac.mu.Unlock()

	logger.Info.Println("Authentication successful")
	return nil
}

// RefreshAccessToken uses the refresh token to get a new access token.
func (ac *APIClient) RefreshAccessToken() error {
	ac.mu.RLock()
	rt := ac.refreshToken
	ac.mu.RUnlock()

	if rt == "" {
		return fmt.Errorf("no refresh token available, re-authentication required")
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"web"},
	}

	resp, err := ac.httpClient.PostForm(ac.baseURL+"/identity/connect/token", data)
	if err != nil {
		return fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("decode refresh response: %w", err)
	}

	// A 200 without a token is a failed refresh; reporting success would hide it from the re-auth fallback.
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("refresh response contained an empty access token")
	}

	ac.mu.Lock()
	ac.accessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		ac.refreshToken = tokenResp.RefreshToken
	}
	ac.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	ac.mu.Unlock()

	logger.Debug.Println("Token refreshed successfully")
	return nil
}

// refreshOrReauthenticate renews credentials: refresh grant first, full login as fallback (#22).
// Serialized on renewMu so concurrent callers cost one login, not one each.
// The skip compares staleToken, not tokenExpiry: a 401'd token is dead while its expiry can still be an hour out.
func (ac *APIClient) refreshOrReauthenticate(staleToken string) error {
	ac.renewMu.Lock()
	defer ac.renewMu.Unlock()

	ac.mu.RLock()
	current := ac.accessToken
	ac.mu.RUnlock()
	if current != staleToken {
		logger.Debug.Println("Credentials already renewed by a concurrent caller, skipping")
		return nil
	}

	refreshErr := ac.RefreshAccessToken()
	if refreshErr == nil {
		return nil
	}

	logger.Warn.Printf("Token refresh failed, attempting full re-authentication: %v", refreshErr)
	if authErr := ac.Authenticate(); authErr != nil {
		return fmt.Errorf("refresh failed (%v); re-authentication failed: %w", refreshErr, authErr)
	}
	return nil
}

// EnsureValidToken refreshes the access token if it's expired or about to expire.
func (ac *APIClient) EnsureValidToken() error {
	// One snapshot: refreshOrReauthenticate compares the token it is handed against the current one.
	ac.mu.RLock()
	expiry := ac.tokenExpiry
	token := ac.accessToken
	ac.mu.RUnlock()

	// Refresh 60 seconds before actual expiry.
	if time.Now().After(expiry.Add(-60 * time.Second)) {
		logger.Debug.Println("Token expiring soon, refreshing...")
		return ac.refreshOrReauthenticate(token)
	}
	return nil
}

// SyncNameMaps holds decrypted display names keyed by Vaultwarden UUID (from sync).
type SyncNameMaps struct {
	Organizations map[string]string // organization id -> name (decrypted with user symmetric key)
	Folders       map[string]string // folder id -> name (decrypted with user symmetric key)
	Collections   map[string]string // collection id -> name (decrypted with org symmetric key)
}

func emptySyncNameMaps() SyncNameMaps {
	return SyncNameMaps{
		Organizations: make(map[string]string),
		Folders:       make(map[string]string),
		Collections:   make(map[string]string),
	}
}

// decryptVaultLabel decrypts a cipher string using the given keys in order.
// decryptVaultLabel decrypts a cipher string using the given keys in order.
// The entityKind and entityID are used for tracing during logging.
func decryptVaultLabel(raw, entityKind, entityID string, keys ...SymmetricKey) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, k := range keys {
		if len(k.EncKey) == 0 {
			continue
		}
		out, err := DecryptStr(raw, k)
		if err == nil && out != "" {
			return out
		}
	}
	// If not a ciphertext, return as-is
	// NOTE: This does not mean that the decryption will silently fail and return the raw value if
	// the decryption fails during MAC verification (that part still throws an error as it should)
	if _, err := ParseCipherString(raw); err != nil {
		return raw
	}
	logger.Warn.Printf("decryptVaultLabel: could not decrypt ciphertext-form %s name (id=%s)", entityKind, entityID)
	return ""
}

// buildSyncNameMaps decrypts organization, folder, and collection names from a sync response.
// Organization names are tried with the user symmetric key first, then that org's symmetric key
// Folder names use the user key; collection names use the org key.
func buildSyncNameMaps(syncResp SyncResponse, userKey SymmetricKey, orgKeys map[string]SymmetricKey) SyncNameMaps {
	out := emptySyncNameMaps()

	for _, org := range syncResp.Profile.Organizations {
		if org.ID == "" {
			continue
		}
		var keys []SymmetricKey
		keys = append(keys, userKey)
		if k, ok := orgKeys[org.ID]; ok {
			keys = append(keys, k)
		}
		name := decryptVaultLabel(org.Name, "organization", org.ID, keys...)
		if name == "" {
			logger.Debug.Printf("Empty organization display name for org %s (raw len=%d)", org.ID, len(org.Name))
			continue
		}
		out.Organizations[org.ID] = name
	}

	for _, f := range syncResp.Folders {
		if f.ID == "" {
			continue
		}
		name := decryptVaultLabel(f.Name, "folder", f.ID, userKey)
		if name == "" {
			logger.Debug.Printf("Empty folder name for folder %s", f.ID)
			continue
		}
		out.Folders[f.ID] = name
	}

	for _, col := range syncResp.Collections {
		if col.ID == "" || col.OrganizationID == "" {
			continue
		}
		orgKey, ok := orgKeys[col.OrganizationID]
		if !ok {
			logger.Debug.Printf("No org key for collection %s (org %s), skipping name decrypt", col.ID, col.OrganizationID)
			continue
		}
		name := decryptVaultLabel(col.Name, "collection", col.ID, orgKey)
		if name == "" {
			logger.Debug.Printf("Empty collection name for collection %s", col.ID)
			continue
		}
		out.Collections[col.ID] = name
	}

	return out
}

// LookupIDByName returns an id whose display name equals target (case-insensitive, trimmed).
// If several ids share that name, it returns the lexicographically smallest id.
func LookupIDByName(idToName map[string]string, target string) (id string, ok bool) {
	target = strings.TrimSpace(target)
	if target == "" || len(idToName) == 0 {
		return "", false
	}
	var matches []string
	for id, n := range idToName {
		if strings.EqualFold(strings.TrimSpace(n), target) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 0 {
		return "", false
	}
	sort.Strings(matches)
	return matches[0], true
}

// FailedCipher identifies a cipher that failed to decrypt, carrying the placement the sync
// payload reports for it in plaintext.
type FailedCipher struct {
	ID             string
	OrganizationID string
	FolderID       string
	CollectionIDs  []string
}

// newFailedCipher records a decrypt failure with its current placement, normalized as decryptCipher does.
func newFailedCipher(c SyncCipher) FailedCipher {
	f := FailedCipher{ID: c.ID}
	if c.OrganizationID != nil {
		f.OrganizationID = strings.TrimSpace(*c.OrganizationID)
	}
	if c.FolderID != nil {
		f.FolderID = strings.TrimSpace(*c.FolderID)
	}
	if len(c.CollectionIDs) > 0 {
		f.CollectionIDs = append([]string(nil), c.CollectionIDs...)
	}
	return f
}

// Sync fetches and decrypts all vault items and returns them along with maps of decrypted
// organization, folder, and collection names, plus the ciphers that failed to decrypt and
// their current placement (trashed ciphers are skipped, not failures). The failure list is
// also returned with the error raised when nothing decrypted.
func (ac *APIClient) Sync() ([]DecryptedItem, SyncNameMaps, []FailedCipher, error) {
	if err := ac.EnsureValidToken(); err != nil {
		return nil, emptySyncNameMaps(), nil, fmt.Errorf("ensure valid token: %w", err)
	}

	ac.mu.RLock()
	token := ac.accessToken
	key := ac.symKey
	ac.mu.RUnlock()

	req, err := http.NewRequest("GET", ac.baseURL+"/api/sync", nil)
	if err != nil {
		return nil, emptySyncNameMaps(), nil, fmt.Errorf("create sync request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return nil, emptySyncNameMaps(), nil, fmt.Errorf("sync request: %w", err)
	}

	retriedAfterRenewal := false
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warn.Printf("close sync 401 response body: %v", closeErr)
		}

		// Renew and retry once; pass the token that drew the 401 so a concurrent renewal isn't repeated.
		if err := ac.refreshOrReauthenticate(token); err != nil {
			return nil, emptySyncNameMaps(), nil, fmt.Errorf("sync auth failed: %w", err)
		}
		ac.mu.RLock()
		token = ac.accessToken
		key = ac.symKey // Authenticate() may have rotated it
		ac.mu.RUnlock()

		retriedAfterRenewal = true
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = ac.httpClient.Do(req)
		if err != nil {
			return nil, emptySyncNameMaps(), nil, fmt.Errorf("sync retry: %w", err)
		}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn.Printf("close sync response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if retriedAfterRenewal && resp.StatusCode == http.StatusUnauthorized {
			// Renewal succeeded but the server still rejects the token (revoked session).
			// Zero the expiry, or EnsureValidToken no-ops every tick and the cache freezes.
			ac.mu.Lock()
			ac.tokenExpiry = time.Time{}
			ac.mu.Unlock()
			return nil, emptySyncNameMaps(), nil, fmt.Errorf(
				"sync failed (HTTP %d) after token refresh/re-auth; forcing re-auth on next attempt: %s",
				resp.StatusCode, string(body))
		}
		return nil, emptySyncNameMaps(), nil, fmt.Errorf("sync failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var syncResp SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return nil, emptySyncNameMaps(), nil, fmt.Errorf("decode sync response: %w", err)
	}

	// Decrypt org keys if organizations are present.
	orgKeys := make(map[string]SymmetricKey)
	if len(syncResp.Profile.Organizations) > 0 && syncResp.Profile.PrivateKey != "" {
		privateKey, err := DecryptPrivateKey(syncResp.Profile.PrivateKey, key)
		if err != nil {
			logger.Warn.Printf("Failed to decrypt RSA private key, org items will be skipped: %v", err)
		} else {
			for _, org := range syncResp.Profile.Organizations {
				orgKey, err := DecryptOrgKey(org.Key, privateKey)
				if err != nil {
					logger.Warn.Printf("Failed to decrypt org key for %s: %v", org.ID, err)
					continue
				}
				orgKeys[org.ID] = orgKey
				logger.Debug.Printf("Decrypted org key for organization %s", org.ID)
			}
			logger.Info.Printf("Decrypted %d organization key(s)", len(orgKeys))
		}
	}

	// Decrypt all ciphers.
	items := make([]DecryptedItem, 0, len(syncResp.Ciphers))
	var failed []FailedCipher
	for _, c := range syncResp.Ciphers {
		// Trashed ciphers stay in the sync payload; they must not resolve (#20).
		if c.DeletedDate != nil && strings.TrimSpace(*c.DeletedDate) != "" {
			logger.Debug.Printf("Skipping trashed cipher %s", c.ID)
			continue
		}

		// Select the correct decryption key.
		decryptKey := key
		if c.OrganizationID != nil && *c.OrganizationID != "" {
			if orgKey, ok := orgKeys[*c.OrganizationID]; ok {
				decryptKey = orgKey
			} else {
				logger.Debug.Printf("No org key for cipher %s (org %s), skipping", c.ID, *c.OrganizationID)
				if c.ID != "" {
					failed = append(failed, newFailedCipher(c))
				}
				continue
			}
		}

		item, err := decryptCipher(c, decryptKey)
		if err != nil {
			logger.Debug.Printf("Failed to decrypt cipher %s: %v", c.ID, err)
			if c.ID != "" {
				failed = append(failed, newFailedCipher(c))
			}
			continue
		}
		items = append(items, item)
	}

	// Nothing decrypted while ciphers failed means a broken key, not an empty vault:
	// succeeding here would let syncVault replace a healthy cache with an empty one.
	if len(items) == 0 && len(failed) > 0 {
		return nil, emptySyncNameMaps(), failed, fmt.Errorf(
			"sync decrypted 0 of %d ciphers (%d failures), refusing to replace cache",
			len(syncResp.Ciphers), len(failed))
	}

	logger.Info.Printf("Synced and decrypted %d vault items", len(items))

	nameMaps := buildSyncNameMaps(syncResp, key, orgKeys)

	logger.Info.Printf(
		"Synced %d organizations, %d folders, and %d collections",
		len(syncResp.Profile.Organizations),
		len(syncResp.Folders),
		len(syncResp.Collections),
	)

	return items, nameMaps, failed, nil
}

// DecryptedItem is a decrypted vault item ready for cache lookup.
type DecryptedItem struct {
	ID             string
	Type           int
	Name           string
	Username       string
	Password       string
	Notes          string
	URI            string
	Fields         map[string]string
	OrganizationID string
	CollectionIDs  []string
	FolderID       string
}

// decryptCipher decrypts a single vault cipher into a DecryptedItem.
func decryptCipher(c SyncCipher, key SymmetricKey) (DecryptedItem, error) {
	item := DecryptedItem{
		ID:     c.ID,
		Type:   c.Type,
		Fields: make(map[string]string),
	}

	var err error
	item.Name, err = DecryptStr(c.Name, key)
	if err != nil {
		return item, fmt.Errorf("decrypt name: %w", err)
	}

	if c.Notes != nil {
		item.Notes, _ = DecryptStr(*c.Notes, key)
	}

	if c.Login != nil {
		if c.Login.Username != nil {
			item.Username, _ = DecryptStr(*c.Login.Username, key)
		}
		if c.Login.Password != nil {
			item.Password, _ = DecryptStr(*c.Login.Password, key)
		}
		if c.Login.URI != nil {
			item.URI, _ = DecryptStr(*c.Login.URI, key)
		}
		if item.URI == "" && len(c.Login.URIs) > 0 && c.Login.URIs[0].URI != nil {
			item.URI, _ = DecryptStr(*c.Login.URIs[0].URI, key)
		}
	}

	for _, f := range c.Fields {
		var name, value string
		if f.Name != nil {
			name, _ = DecryptStr(*f.Name, key)
		}
		if f.Value != nil {
			value, _ = DecryptStr(*f.Value, key)
		}
		if name != "" {
			item.Fields[name] = value
		}
	}

	if c.OrganizationID != nil {
		item.OrganizationID = strings.TrimSpace(*c.OrganizationID)
	}
	if len(c.CollectionIDs) > 0 {
		item.CollectionIDs = append([]string(nil), c.CollectionIDs...)
	}
	if c.FolderID != nil {
		item.FolderID = strings.TrimSpace(*c.FolderID)
	}

	return item, nil
}

// prelogin fetches KDF parameters for the given email.
func (ac *APIClient) prelogin() (*PreloginResponse, error) {
	body := fmt.Sprintf(`{"email":"%s"}`, ac.email)
	resp, err := ac.httpClient.Post(
		ac.baseURL+"/identity/accounts/prelogin",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("prelogin request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("prelogin failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result PreloginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode prelogin: %w", err)
	}

	return &result, nil
}

// loginWithPassword authenticates with email + hashed password (requires no 2FA or 2FA handling).
func (ac *APIClient) loginWithPassword(hashedPassword string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":       {"password"},
		"username":         {ac.email},
		"password":         {hashedPassword},
		"scope":            {"api offline_access"},
		"client_id":        {"web"},
		"deviceType":       {"14"},
		"deviceIdentifier": {ac.deviceID},
		"deviceName":       {"vaultwarden-api"},
	}

	return ac.doTokenRequest(data)
}

// loginWithAPIKey authenticates with API key (client_credentials). Bypasses 2FA.
func (ac *APIClient) loginWithAPIKey() (*TokenResponse, error) {
	data := url.Values{
		"grant_type":       {"client_credentials"},
		"client_id":        {ac.clientID},
		"client_secret":    {ac.clientSecret},
		"scope":            {"api"},
		"deviceType":       {"14"},
		"deviceIdentifier": {ac.deviceID},
		"deviceName":       {"vaultwarden-api"},
	}

	return ac.doTokenRequest(data)
}

// doTokenRequest sends a token request and parses the response.
func (ac *APIClient) doTokenRequest(data url.Values) (*TokenResponse, error) {
	resp, err := ac.httpClient.PostForm(ac.baseURL+"/identity/connect/token", data)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode login response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("login response contained an empty access token")
	}

	return &tokenResp, nil
}

// fetchProfileKey gets the encrypted symmetric key from the user's profile.
// Used when API key login doesn't return the Key in the token response.
// The token is passed in because Authenticate has not published it yet.
func (ac *APIClient) fetchProfileKey(token string) (string, error) {
	req, err := http.NewRequest("GET", ac.baseURL+"/api/sync", nil)
	if err != nil {
		return "", fmt.Errorf("create sync request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sync request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("sync failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var syncResp SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return "", fmt.Errorf("decode sync: %w", err)
	}

	if syncResp.Profile.Key == "" {
		return "", fmt.Errorf("profile key is empty")
	}

	return syncResp.Profile.Key, nil
}
