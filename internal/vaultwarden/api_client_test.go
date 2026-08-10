package vaultwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOrgID        = "11111111-1111-4111-8111-111111111111"
	testOrgID2       = "22222222-2222-4222-8222-222222222222"
	testFolderID     = "33333333-3333-4333-8333-333333333333"
	testCollectionID = "44444444-4444-4444-8444-444444444444"
)

// testUserKey generates a test symmetric key for the user.
func testUserKey() SymmetricKey {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i)
	}
	for i := range macKey {
		macKey[i] = byte(i + 32)
	}
	return SymmetricKey{EncKey: encKey, MacKey: macKey}
}

// testOrgKey generates a test symmetric key for the organization.
func testOrgKey() SymmetricKey {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i + 64)
	}
	for i := range macKey {
		macKey[i] = byte(i + 96)
	}
	return SymmetricKey{EncKey: encKey, MacKey: macKey}
}

// encryptType2Cipher builds a Bitwarden type-2 cipher string for unit tests.
func encryptType2Cipher(plaintext string, key SymmetricKey) (string, error) {
	return encryptType2CipherBytes([]byte(plaintext), key)
}

// encryptType2CipherBytes builds a Bitwarden type-2 cipher string over raw bytes.
func encryptType2CipherBytes(data []byte, key SymmetricKey) (string, error) {
	padLen := aes.BlockSize - (len(data) % aes.BlockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 7)
	}

	block, err := aes.NewCipher(key.EncKey)
	if err != nil {
		return "", err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, key.MacKey)
	mac.Write(iv)
	mac.Write(ct)
	macBytes := mac.Sum(nil)

	return fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(macBytes),
	), nil
}

// mustEncryptType2Cipher encrypts a plaintext string using the given symmetric key and returns the encrypted string.
func mustEncryptType2Cipher(t *testing.T, plaintext string, key SymmetricKey) string {
	t.Helper()
	s, err := encryptType2Cipher(plaintext, key)
	if err != nil {
		t.Fatalf("encryptType2Cipher: %v", err)
	}
	return s
}

// newSyncTestClient returns an APIClient in authenticated state pointed at a test server.
func newSyncTestClient(t *testing.T, handler http.Handler) *APIClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	ac := NewAPIClient(srv.URL, "user@example.com", "password", "", "")
	ac.accessToken = "test-token"
	ac.refreshToken = "test-refresh-token"
	ac.tokenExpiry = time.Now().Add(time.Hour)
	ac.symKey = testUserKey()
	return ac
}

func TestSync_SkipsTrashedCiphers(t *testing.T) {
	userKey := testUserKey()
	deleted := "2026-08-01T12:00:00.000000Z"

	// Encrypt here, not in the handler: t.Fatalf from a handler goroutine is undefined.
	activeName := mustEncryptType2Cipher(t, "active-item", userKey)
	trashedName := mustEncryptType2Cipher(t, "trashed-item", userKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{
					ID:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
					Type: CipherTypeLogin,
					Name: activeName,
				},
				{
					ID:          "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
					Type:        CipherTypeLogin,
					Name:        trashedName,
					DeletedDate: &deleted,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	items, _, _, err := ac.Sync(t.Context())
	if err != nil {
		t.Fatalf("Sync() error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Sync() returned %d items, want 1 (trashed cipher must be skipped)", len(items))
	}
	if items[0].Name != "active-item" {
		t.Errorf("surviving item = %q, want active-item", items[0].Name)
	}
}

func TestSync_401RefreshFailsFallsBackToFullReauth(t *testing.T) {
	const testKDFIterations = 10000 // low on purpose: keeps the test fast

	// Stands in for a key rotation: Sync must retry with this key, not the pre-401 snapshot.
	rotatedKey := testOrgKey()
	cipherName := mustEncryptType2Cipher(t, "after-reauth", rotatedKey)

	// The enc||mac blob under the stretched master key is what DecryptSymmetricKey unwraps.
	masterKey, err := MakeMasterKey("password", "user@example.com", KdfPBKDF2, testKDFIterations, nil, nil)
	if err != nil {
		t.Fatalf("MakeMasterKey: %v", err)
	}
	stretched, err := StretchKey(masterKey)
	if err != nil {
		t.Fatalf("StretchKey: %v", err)
	}
	keyBlob := make([]byte, 0, 64)
	keyBlob = append(keyBlob, rotatedKey.EncKey...)
	keyBlob = append(keyBlob, rotatedKey.MacKey...)
	encryptedUserKey, err := encryptType2CipherBytes(keyBlob, stretched)
	if err != nil {
		t.Fatalf("encryptType2CipherBytes: %v", err)
	}

	var syncCalls, refreshCalls, preloginCalls, passwordGrantCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		syncCalls++
		// Only the token minted by the full re-authentication is accepted.
		if r.Header.Get("Authorization") != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{
					ID:   "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
					Type: CipherTypeLogin,
					Name: cipherName,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		preloginCalls++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(PreloginResponse{KDF: KdfPBKDF2, KDFIterations: testKDFIterations}); err != nil {
			t.Errorf("encode prelogin response: %v", err)
		}
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch grant := r.PostFormValue("grant_type"); grant {
		case "refresh_token":
			// Refresh token is dead too (server restart / rotation / revocation).
			refreshCalls++
			w.WriteHeader(http.StatusBadRequest)
		case "password":
			passwordGrantCalls++
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  "new-token",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
				RefreshToken: "new-refresh-token",
				Key:          encryptedUserKey,
			}); err != nil {
				t.Errorf("encode token response: %v", err)
			}
		default:
			t.Errorf("unexpected grant_type %q", grant)
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	ac := newSyncTestClient(t, mux)

	items, _, _, err := ac.Sync(t.Context())
	if err != nil {
		t.Fatalf("Sync() error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Sync() returned %d items, want 1", len(items))
	}
	if items[0].Name != "after-reauth" {
		t.Errorf("item name = %q, want after-reauth", items[0].Name)
	}
	if refreshCalls != 1 {
		t.Errorf("refresh grant calls = %d, want 1", refreshCalls)
	}
	if preloginCalls != 1 {
		t.Errorf("prelogin calls = %d, want 1 (full re-authentication must be attempted) (#22)", preloginCalls)
	}
	if passwordGrantCalls != 1 {
		t.Errorf("password grant calls = %d, want 1 (full re-authentication must be attempted) (#22)", passwordGrantCalls)
	}
	if syncCalls != 2 {
		t.Errorf("sync calls = %d, want 2 (one 401, one retry after re-auth)", syncCalls)
	}
}

func TestSync_401ReauthAlsoFailsReturnsError(t *testing.T) {
	var preloginCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		preloginCalls++
		w.WriteHeader(http.StatusInternalServerError)
	})

	ac := newSyncTestClient(t, mux)

	_, _, _, err := ac.Sync(t.Context())
	if err == nil {
		t.Fatal("Sync() expected error")
	}
	if preloginCalls == 0 {
		t.Error("full re-authentication was never attempted after refresh failure (#22)")
	}
	if !strings.Contains(err.Error(), "re-authentication failed") {
		t.Errorf("error %q should mention re-authentication failure", err)
	}
}

func TestSync_AllCiphersFailToDecryptReturnsError(t *testing.T) {
	// Encrypted under a key the client does not hold, so every cipher fails its MAC check.
	wrongKey := testOrgKey()
	nameA := mustEncryptType2Cipher(t, "item-a", wrongKey)
	nameB := mustEncryptType2Cipher(t, "item-b", wrongKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Type: CipherTypeLogin, Name: nameA},
				{ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Type: CipherTypeLogin, Name: nameB},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	items, _, failed, err := ac.Sync(t.Context())
	if err == nil {
		t.Fatalf("Sync() returned %d items and no error; want an error when every cipher fails to decrypt", len(items))
	}
	if !strings.Contains(err.Error(), "decrypted 0 of 2") {
		t.Errorf("error %q should report how many of the ciphers decrypted", err)
	}
	if len(failed) != 2 {
		t.Errorf("failed ciphers = %v, want both reported alongside the error", failed)
	}
}

func TestSync_OrgCipherWithoutOrgKeyCountsAsFailure(t *testing.T) {
	// No profile private key, so no org key can be derived. The name is encrypted under
	// the *user* key on purpose: it would decrypt fine if the cipher were ever attempted.
	userKey := testUserKey()
	orgID := testOrgID
	orgName := mustEncryptType2Cipher(t, "org-item", userKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Profile: SyncProfile{
				Organizations: []SyncOrganization{{ID: orgID, Name: "Org"}},
			},
			Ciphers: []SyncCipher{
				{
					ID:             "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
					Type:           CipherTypeLogin,
					OrganizationID: &orgID,
					Name:           orgName,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	items, _, _, err := ac.Sync(t.Context())
	if err == nil {
		t.Fatalf("Sync() returned %d items and no error; want an error when the only cipher is org-owned and no org key is available", len(items))
	}
	if !strings.Contains(err.Error(), "refusing to replace cache") {
		t.Errorf("error %q should refuse to replace the cache", err)
	}
	if !strings.Contains(err.Error(), "decrypted 0 of 1") {
		t.Errorf("error %q should count the skipped org cipher as a failure", err)
	}
}

func TestSync_ReportsFailedCiphersWithPlacement(t *testing.T) {
	userKey := testUserKey()
	wrongKey := testOrgKey()
	orgID := testOrgID
	folderID := "  " + testFolderID + "  " // padded: placement must be normalized like decryptCipher does
	deleted := "2026-08-01T12:00:00.000000Z"

	const (
		okID      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		badMACID  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		orgItemID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		trashedID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	)

	okName := mustEncryptType2Cipher(t, "ok-item", userKey)
	badMACName := mustEncryptType2Cipher(t, "bad-mac-item", wrongKey)
	orgName := mustEncryptType2Cipher(t, "org-item", userKey)
	trashedName := mustEncryptType2Cipher(t, "trashed-item", userKey)
	noIDName := mustEncryptType2Cipher(t, "no-id-item", wrongKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			// No profile private key, so the org key is never derived.
			Profile: SyncProfile{Organizations: []SyncOrganization{{ID: orgID, Name: "Org"}}},
			Ciphers: []SyncCipher{
				{ID: okID, Type: CipherTypeLogin, Name: okName},
				{ID: badMACID, Type: CipherTypeLogin, Name: badMACName, FolderID: &folderID},
				{
					ID:             orgItemID,
					Type:           CipherTypeLogin,
					OrganizationID: &orgID,
					CollectionIDs:  []string{testCollectionID},
					Name:           orgName,
				},
				{ID: trashedID, Type: CipherTypeLogin, Name: trashedName, DeletedDate: &deleted},
				{ID: "", Type: CipherTypeLogin, Name: noIDName},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	items, _, failed, err := ac.Sync(t.Context())
	if err != nil {
		t.Fatalf("Sync() error: %v", err)
	}
	if len(items) != 1 || items[0].ID != okID {
		t.Fatalf("Sync() returned %d items, want only %s", len(items), okID)
	}

	byID := make(map[string]FailedCipher, len(failed))
	for _, f := range failed {
		byID[f.ID] = f
	}
	if _, ok := byID[badMACID]; !ok {
		t.Errorf("failed ciphers %v should include the bad-MAC cipher %s", failed, badMACID)
	}
	if _, ok := byID[orgItemID]; !ok {
		t.Errorf("failed ciphers %v should include the org cipher with no usable org key %s", failed, orgItemID)
	}
	if _, ok := byID[trashedID]; ok {
		t.Errorf("failed ciphers %v must not include the trashed cipher %s", failed, trashedID)
	}
	if _, ok := byID[""]; ok {
		t.Errorf("failed ciphers %v must not include the cipher with an empty ID", failed)
	}
	if len(failed) != 2 {
		t.Errorf("failed ciphers = %v, want exactly 2", failed)
	}

	if got := byID[badMACID].FolderID; got != testFolderID {
		t.Errorf("bad-MAC cipher folder = %q, want the trimmed payload folder %q", got, testFolderID)
	}
	if got := byID[orgItemID].OrganizationID; got != orgID {
		t.Errorf("org cipher organization = %q, want %q", got, orgID)
	}
	cols := byID[orgItemID].CollectionIDs
	if len(cols) != 1 || cols[0] != testCollectionID {
		t.Errorf("org cipher collections = %v, want [%s]", cols, testCollectionID)
	}
}

func TestSync_OnlyTrashedCiphersSyncsEmpty(t *testing.T) {
	// An all-trashed vault is empty, not broken: trashed skips are not decrypt failures.
	userKey := testUserKey()
	deleted := "2026-08-01T12:00:00.000000Z"
	trashedName := mustEncryptType2Cipher(t, "trashed-item", userKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{
					ID:          "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
					Type:        CipherTypeLogin,
					Name:        trashedName,
					DeletedDate: &deleted,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	items, _, _, err := ac.Sync(t.Context())
	if err != nil {
		t.Fatalf("Sync() error: %v (an all-trashed vault is empty, not failed)", err)
	}
	if len(items) != 0 {
		t.Fatalf("Sync() returned %d items, want 0", len(items))
	}
}

func TestSync_RetryStill401ForcesReauthOnNextAttempt(t *testing.T) {
	// The refresh grant mints a token the API still rejects (revoked session).
	var syncCalls, refreshCalls, preloginCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		syncCalls++
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		preloginCalls++
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		refreshCalls++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "refreshed-but-rejected-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			RefreshToken: "another-refresh-token",
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	_, _, _, err := ac.Sync(t.Context())
	if err == nil {
		t.Fatal("Sync() expected error")
	}
	if !strings.Contains(err.Error(), "forcing re-auth on next attempt") {
		t.Errorf("error %q should say the next attempt is forced to re-authenticate", err)
	}
	ac.mu.RLock()
	expiry := ac.tokenExpiry
	ac.mu.RUnlock()
	if !expiry.IsZero() {
		t.Errorf("tokenExpiry = %v, want zero so EnsureValidToken re-runs the recovery ladder", expiry)
	}
	if syncCalls != 2 {
		t.Errorf("sync calls = %d, want 2 (one 401, one retry — no extra retry loops)", syncCalls)
	}
	if refreshCalls != 1 {
		t.Errorf("token endpoint calls = %d, want 1 (refresh succeeded, so no in-flight re-auth)", refreshCalls)
	}
	if preloginCalls != 0 {
		t.Errorf("prelogin calls = %d, want 0 (recovery is deferred to the next attempt)", preloginCalls)
	}
}

func TestSync_ConcurrentRenewalRunsOneLogin(t *testing.T) {
	const staleToken = "test-token" // what newSyncTestClient seeds
	const renewedToken = "renewed-token"
	const callers = 2

	userKey := testUserKey()
	cipherName := mustEncryptType2Cipher(t, "after-renewal", userKey)

	var mu sync.Mutex
	var tokenCalls, syncCalls, staleSyncCalls int

	// Barrier: hold every caller at the 401 until all have seen it, so they really do
	// observe the same dead token concurrently.
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		syncCalls++
		stale := r.Header.Get("Authorization") != "Bearer "+renewedToken
		if stale {
			staleSyncCalls++
			if staleSyncCalls == callers {
				close(release)
			}
		}
		mu.Unlock()

		if stale {
			select {
			case <-release:
			case <-time.After(5 * time.Second):
				t.Error("timed out waiting for all callers to reach the 401")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Type: CipherTypeLogin, Name: cipherName},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokenCalls++
		mu.Unlock()

		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if grant := r.PostFormValue("grant_type"); grant != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", grant)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  renewedToken,
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			RefreshToken: "renewed-refresh-token",
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	})
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		t.Error("full re-authentication attempted, but the refresh grant succeeds here")
		w.WriteHeader(http.StatusInternalServerError)
	})

	ac := newSyncTestClient(t, mux)
	if ac.accessToken != staleToken {
		t.Fatalf("seeded accessToken = %q, want %q", ac.accessToken, staleToken)
	}

	var wg sync.WaitGroup
	errs := make([]error, callers)
	counts := make([]int, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			items, _, _, err := ac.Sync(t.Context())
			errs[i] = err
			counts[i] = len(items)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Sync() #%d error: %v", i, err)
		}
		if counts[i] != 1 {
			t.Errorf("Sync() #%d returned %d items, want 1", i, counts[i])
		}
	}
	if tokenCalls != 1 {
		t.Errorf("token endpoint calls = %d, want 1 (concurrent renewals must collapse into one)", tokenCalls)
	}
	if syncCalls != 2*callers {
		t.Errorf("sync calls = %d, want %d (one 401 and one retry per caller)", syncCalls, 2*callers)
	}
}

func TestRefreshAccessToken_EmptyAccessTokenIsError(t *testing.T) {
	// A 200 with no access_token must not be success: it would store an empty bearer token.
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{}`)); err != nil {
			t.Errorf("write token response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	if err := ac.RefreshAccessToken(t.Context()); err == nil {
		t.Fatal("RefreshAccessToken() expected error for a 200 response with an empty access_token")
	}

	ac.mu.RLock()
	token := ac.accessToken
	ac.mu.RUnlock()
	if token != "test-token" {
		t.Errorf("accessToken = %q, want the prior token left untouched", token)
	}
}

func TestDoTokenRequest_EmptyAccessTokenIsError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"expires_in":3600,"token_type":"Bearer"}`)); err != nil {
			t.Errorf("write token response: %v", err)
		}
	})

	ac := newSyncTestClient(t, mux)

	if _, err := ac.doTokenRequest(t.Context(), url.Values{"grant_type": {"password"}}); err == nil {
		t.Fatal("doTokenRequest() expected error for a 200 response with an empty access_token")
	}
}

func TestAuthenticate_ProfileKeyFailureLeavesPriorStateIntact(t *testing.T) {
	const testKDFIterations = 10000 // low on purpose: keeps the test fast

	// API key login carries no Key, so the profile fetch supplies it; when that fails,
	// a half-applied login (new token, old symKey) would decrypt nothing.
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(PreloginResponse{KDF: KdfPBKDF2, KDFIterations: testKDFIterations}); err != nil {
			t.Errorf("encode prelogin response: %v", err)
		}
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "half-applied-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			RefreshToken: "half-applied-refresh-token",
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	})
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ac := NewAPIClient(srv.URL, "user@example.com", "password", "client-id", "client-secret")
	priorExpiry := time.Now().Add(time.Hour)
	ac.accessToken = "old-token"
	ac.refreshToken = "old-refresh-token"
	ac.tokenExpiry = priorExpiry
	ac.symKey = testUserKey()

	if err := ac.Authenticate(t.Context()); err == nil {
		t.Fatal("Authenticate() expected error when the profile key fetch fails")
	}

	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if ac.accessToken != "old-token" {
		t.Errorf("accessToken = %q, want old-token (failed login must not publish)", ac.accessToken)
	}
	if ac.refreshToken != "old-refresh-token" {
		t.Errorf("refreshToken = %q, want old-refresh-token (failed login must not publish)", ac.refreshToken)
	}
	if !ac.tokenExpiry.Equal(priorExpiry) {
		t.Errorf("tokenExpiry = %v, want %v (failed login must not publish)", ac.tokenExpiry, priorExpiry)
	}
	// The token fields staying put is only meaningful if the key did too.
	priorKey := testUserKey()
	if !bytes.Equal(ac.symKey.EncKey, priorKey.EncKey) {
		t.Error("symKey.EncKey changed, want the prior key left untouched (failed login must not publish)")
	}
	if !bytes.Equal(ac.symKey.MacKey, priorKey.MacKey) {
		t.Error("symKey.MacKey changed, want the prior key left untouched (failed login must not publish)")
	}
}

func TestEmptySyncNameMaps(t *testing.T) {
	t.Parallel()

	// Test that the function generates empty maps
	m := emptySyncNameMaps()
	if m.Organizations == nil || m.Folders == nil || m.Collections == nil {
		t.Fatal("expected non-nil maps")
	}
	if len(m.Organizations)+len(m.Folders)+len(m.Collections) != 0 {
		t.Fatal("expected empty maps")
	}

	// Test that the function generates a new object each time it is called
	m.Organizations["x"] = "y"
	m2 := emptySyncNameMaps()
	if _, ok := m2.Organizations["x"]; ok {
		t.Fatal("maps should not be shared between calls")
	}
}

func TestDecryptVaultLabel(t *testing.T) {
	userKey := testUserKey()
	wrongKey := testOrgKey()
	encrypted := mustEncryptType2Cipher(t, "Secret Org", userKey)
	encryptedNope := mustEncryptType2Cipher(t, "Nope", userKey)

	tests := []struct {
		name string
		raw  string
		keys []SymmetricKey
		want string
	}{
		// Check that empty input returns empty string
		{"empty", "", nil, ""},
		// Check that plaintext is passed through as-is
		{"plaintext passthrough", "Plain Org", []SymmetricKey{userKey}, "Plain Org"},
		// Check that encrypted text is decrypted with the given keys
		{"encrypted with user key", encrypted, []SymmetricKey{userKey}, "Secret Org"},
		{"ecnrypted try multiple", encrypted, []SymmetricKey{wrongKey, userKey}, "Secret Org"},
		// Check that wrong key on ciphertext returns empty string
		{"wrong key on ciphertext", encryptedNope, []SymmetricKey{wrongKey}, ""},
		// Check that empty keys only returns empty string
		{"empty keys only", encrypted, []SymmetricKey{{}, {}}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decryptVaultLabel(tt.raw, "organization", testOrgID, tt.keys...)
			if got != tt.want {
				t.Errorf("decryptVaultLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSyncNameMaps(t *testing.T) {
	userKey := testUserKey()
	orgKey := testOrgKey()
	orgKeys := map[string]SymmetricKey{testOrgID: orgKey}

	// Create fake sync response containing test orgs, folders, and collections
	syncResp := SyncResponse{
		Profile: SyncProfile{
			Organizations: []SyncOrganization{
				{ID: testOrgID, Name: "Plain Org"},
				{ID: testOrgID2, Name: mustEncryptType2Cipher(t, "Encrypted Org", userKey)},
			},
		},
		Folders: []SyncFolder{
			{ID: testFolderID, Name: mustEncryptType2Cipher(t, "Work", userKey)},
			{ID: "00000000-0000-4000-8000-000000000099", Name: mustEncryptType2Cipher(t, "Bad", testOrgKey())},
		},
		Collections: []SyncCollection{
			{ID: testCollectionID, OrganizationID: testOrgID, Name: mustEncryptType2Cipher(t, "Shared", orgKey)},
			{ID: "55555555-5555-4555-8555-555555555555", OrganizationID: "99999999-9999-4999-8999-999999999999", Name: "orphan"},
			{ID: "", OrganizationID: testOrgID, Name: "skip-empty-id"},
		},
	}

	maps := buildSyncNameMaps(syncResp, userKey, orgKeys)

	// Test that the function decrypts the organization names correctly
	if got := maps.Organizations[testOrgID]; got != "Plain Org" {
		t.Errorf("plain org name = %q, want Plain Org", got)
	}
	if got := maps.Organizations[testOrgID2]; got != "Encrypted Org" {
		t.Errorf("encrypted org name = %q, want Encrypted Org", got)
	}
	// Test that the function decrypts the folder names correctly
	if got := maps.Folders[testFolderID]; got != "Work" {
		t.Errorf("folder name = %q, want Work", got)
	}
	// Test that the function does not include folders with wrong decrypt key
	if _, ok := maps.Folders["00000000-0000-4000-8000-000000000099"]; ok {
		t.Error("folder with wrong decrypt key should be omitted")
	}
	// Test that the function decrypts the collection names correctly
	if got := maps.Collections[testCollectionID]; got != "Shared" {
		t.Errorf("collection name = %q, want Shared", got)
	}
	// Test that the function does not include collections with empty organization ID
	if len(maps.Collections) != 1 {
		t.Errorf("collections map len = %d, want 1", len(maps.Collections))
	}
}

func TestLookupIDByName(t *testing.T) {
	t.Parallel()

	// The map to run tests on
	idToName := map[string]string{
		"bbb-id": "Acme",
		"aaa-id": "Acme",
		"ccc-id": "Other",
	}

	tests := []struct {
		name   string
		target string
		wantID string
		wantOK bool
	}{
		{"exact match", "Acme", "aaa-id", true},
		{"case insensitive and trimmed", " acme ", "aaa-id", true},
		{"unknown", "Missing", "", false},
		{"empty target", "", "", false},
		{"other name", "other", "ccc-id", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, ok := LookupIDByName(idToName, tt.target)
			if ok != tt.wantOK || id != tt.wantID {
				t.Errorf("LookupIDByName(%q) = (%q, %v), want (%q, %v)", tt.target, id, ok, tt.wantID, tt.wantOK)
			}
		})
	}

	// Test that empty map returns false
	t.Run("empty map", func(t *testing.T) {
		t.Parallel()
		_, ok := LookupIDByName(nil, "Acme")
		if ok {
			t.Error("expected false for empty map")
		}
	})
}
