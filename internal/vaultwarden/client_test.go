package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewClient_withState(t *testing.T) {
	items := map[string]DecryptedItem{
		"c1": {ID: "c1", Name: "db-password", Password: "pw"},
	}
	nameMaps := SyncNameMaps{
		Organizations: map[string]string{testOrgID: "Acme"},
		Folders:       map[string]string{},
		Collections:   map[string]string{},
	}

	c := NewClient(nil, 0, WithState(items, nameMaps))

	val, err := c.GetSecret("db-password", SecretFilter{})
	if err != nil || val != "pw" {
		t.Fatalf("GetSecret() = (%q, %v), want (pw, nil)", val, err)
	}
	if got := c.NameMaps().Organizations[testOrgID]; got != "Acme" {
		t.Errorf("NameMaps org = %q, want Acme", got)
	}
}

func TestMatchesSecretFilter(t *testing.T) {
	t.Parallel()

	base := DecryptedItem{
		ID:             "item-1",
		OrganizationID: testOrgID,
		CollectionIDs:  []string{testCollectionID, "66666666-6666-4666-8666-666666666666"},
		FolderID:       testFolderID,
	}

	tests := []struct {
		name   string
		filter SecretFilter
		want   bool
	}{
		{"empty filter", SecretFilter{}, true},
		{"org match", SecretFilter{OrganizationID: testOrgID}, true},
		{"org case insensitive", SecretFilter{OrganizationID: strings.ToUpper(testOrgID)}, true},
		{"org mismatch", SecretFilter{OrganizationID: testOrgID2}, false},
		{"collection match", SecretFilter{CollectionID: testCollectionID}, true},
		{"collection case insensitive", SecretFilter{CollectionID: strings.ToUpper(testCollectionID)}, true},
		{"collection missing", SecretFilter{CollectionID: "77777777-7777-4777-8777-777777777777"}, false},
		{"folder match", SecretFilter{FolderID: testFolderID}, true},
		{"folder mismatch", SecretFilter{FolderID: "88888888-8888-4888-8888-888888888888"}, false},
		{
			"all dimensions match",
			SecretFilter{
				OrganizationID: testOrgID,
				CollectionID:   testCollectionID,
				FolderID:       testFolderID,
			},
			true,
		},
		{
			"org ok collection fail",
			SecretFilter{OrganizationID: testOrgID, CollectionID: "77777777-7777-4777-8777-777777777777"},
			false,
		},
		// Server-side scope (plural fields).
		{"scope org in set", SecretFilter{OrganizationIDs: []string{testOrgID2, testOrgID}}, true},
		{"scope org not in set", SecretFilter{OrganizationIDs: []string{testOrgID2}}, false},
		{"scope collection intersects", SecretFilter{CollectionIDs: []string{testCollectionID}}, true},
		{
			"scope collection disjoint",
			SecretFilter{CollectionIDs: []string{"77777777-7777-4777-8777-777777777777"}},
			false,
		},
		{
			"scope org and collection both match",
			SecretFilter{OrganizationIDs: []string{testOrgID}, CollectionIDs: []string{testCollectionID}},
			true,
		},
		{
			"scope org ok but collection disjoint",
			SecretFilter{OrganizationIDs: []string{testOrgID}, CollectionIDs: []string{"77777777-7777-4777-8777-777777777777"}},
			false,
		},
		{
			"scope narrowed further by client filter",
			SecretFilter{OrganizationID: testOrgID, OrganizationIDs: []string{testOrgID}},
			true,
		},
		{
			"client filter cannot widen beyond scope",
			SecretFilter{OrganizationID: testOrgID, OrganizationIDs: []string{testOrgID2}},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchesSecretFilter(base, tt.filter); got != tt.want {
				t.Errorf("matchesSecretFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesSecretFilter_PersonalItemExcludedByOrgScope(t *testing.T) {
	t.Parallel()

	// A personal (no-org) item must be excluded once a key scopes to organizations.
	personal := DecryptedItem{ID: "personal-1", Name: "personal-secret"}

	if matchesSecretFilter(personal, SecretFilter{OrganizationIDs: []string{testOrgID}}) {
		t.Error("personal item should be excluded by an org scope")
	}
	if !matchesSecretFilter(personal, SecretFilter{}) {
		t.Error("personal item should match an empty (full-access) scope")
	}
}

func TestSyncVault_RetainsCachedEntriesForFailedCiphers(t *testing.T) {
	userKey := testUserKey()
	wrongKey := testOrgKey()

	const (
		updatedID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" // decrypts: cache entry replaced
		failedID  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" // fails to decrypt: old entry retained
		removedID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" // absent from the payload: dropped
		trashedID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" // trashed in the payload: dropped (#20)
	)

	freshName := mustEncryptType2Cipher(t, "api-key-v2", userKey)
	unreadableName := mustEncryptType2Cipher(t, "org-secret", wrongKey)
	trashedName := mustEncryptType2Cipher(t, "trashed-item", userKey)
	deleted := "2026-08-01T12:00:00.000000Z"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{ID: updatedID, Type: CipherTypeLogin, Name: freshName},
				{ID: failedID, Type: CipherTypeLogin, Name: unreadableName},
				{ID: trashedID, Type: CipherTypeLogin, Name: trashedName, DeletedDate: &deleted},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	old := map[string]DecryptedItem{
		updatedID: {ID: updatedID, Name: "api-key-v1", Password: "old"},
		failedID:  {ID: failedID, Name: "org-secret", Password: "stale-but-present"},
		removedID: {ID: removedID, Name: "removed-item", Password: "gone"},
		trashedID: {ID: trashedID, Name: "trashed-item", Password: "trashed"},
	}
	c := NewClient(newSyncTestClient(t, mux), time.Hour, WithState(old, emptySyncNameMaps()))

	if err := c.syncVault(); err != nil {
		t.Fatalf("syncVault() error: %v", err)
	}

	c.mu.RLock()
	got := maps.Clone(c.items)
	c.mu.RUnlock()

	if len(got) != 2 {
		t.Fatalf("cache holds %d items, want 2: %+v", len(got), got)
	}
	if got[failedID].Password != "stale-but-present" {
		t.Errorf("failed cipher %s = %+v, want the old cached entry retained", failedID, got[failedID])
	}
	if got[updatedID].Name != "api-key-v2" {
		t.Errorf("decrypted cipher %s name = %q, want api-key-v2", updatedID, got[updatedID].Name)
	}
	if _, ok := got[removedID]; ok {
		t.Errorf("cipher %s is absent from the payload and must be dropped", removedID)
	}
	if _, ok := got[trashedID]; ok {
		t.Errorf("cipher %s is trashed in the payload and must be dropped, not retained (#20)", trashedID)
	}
}

func TestSyncVault_RefreshesPlacementOnRetainedEntry(t *testing.T) {
	userKey := testUserKey()
	wrongKey := testOrgKey()

	const (
		okID            = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		movedID         = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		newFolderID     = "99999999-9999-4999-8999-999999999999"
		newCollectionID = "55555555-5555-4555-8555-555555555555"
	)

	okName := mustEncryptType2Cipher(t, "ok-item", userKey)
	unreadableName := mustEncryptType2Cipher(t, "moved-secret", wrongKey)

	// Placement is plaintext in the payload even when the cipher body cannot be decrypted.
	newOrgID := testOrgID2
	newFolder := newFolderID

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{ID: okID, Type: CipherTypeLogin, Name: okName},
				{
					ID:             movedID,
					Type:           CipherTypeLogin,
					Name:           unreadableName,
					OrganizationID: &newOrgID,
					CollectionIDs:  []string{newCollectionID},
					FolderID:       &newFolder,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	old := map[string]DecryptedItem{
		movedID: {
			ID:             movedID,
			Name:           "moved-secret",
			Password:       "stale-but-present",
			OrganizationID: testOrgID,
			CollectionIDs:  []string{testCollectionID},
			FolderID:       testFolderID,
		},
	}
	c := NewClient(newSyncTestClient(t, mux), time.Hour, WithState(old, emptySyncNameMaps()))

	if err := c.syncVault(); err != nil {
		t.Fatalf("syncVault() error: %v", err)
	}

	c.mu.RLock()
	got := maps.Clone(c.items)
	c.mu.RUnlock()

	retained, ok := got[movedID]
	if !ok {
		t.Fatalf("cipher %s should be retained from the previous cache", movedID)
	}
	if retained.Password != "stale-but-present" {
		t.Errorf("retained entry password = %q, want the stale cached value", retained.Password)
	}
	if retained.OrganizationID != testOrgID2 {
		t.Errorf("retained entry org = %q, want the payload org %q", retained.OrganizationID, testOrgID2)
	}
	if retained.FolderID != newFolderID {
		t.Errorf("retained entry folder = %q, want the payload folder %q", retained.FolderID, newFolderID)
	}
	if len(retained.CollectionIDs) != 1 || retained.CollectionIDs[0] != newCollectionID {
		t.Errorf("retained entry collections = %v, want [%s]", retained.CollectionIDs, newCollectionID)
	}
	if matchesSecretFilter(retained, SecretFilter{OrganizationIDs: []string{testOrgID}}) {
		t.Error("retained entry must not be reachable through its stale organization scope")
	}
	if !matchesSecretFilter(retained, SecretFilter{OrganizationIDs: []string{testOrgID2}}) {
		t.Error("retained entry must be reachable through its current organization scope")
	}
	if matchesSecretFilter(retained, SecretFilter{CollectionIDs: []string{testCollectionID}}) {
		t.Error("retained entry must not be reachable through its stale collection scope")
	}
}

func TestSyncVault_RefreshesPlacementWhenEveryCipherFailsToDecrypt(t *testing.T) {
	wrongKey := testOrgKey()

	const (
		movedID         = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		removedID       = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		newFolderID     = "99999999-9999-4999-8999-999999999999"
		newCollectionID = "55555555-5555-4555-8555-555555555555"
	)

	unreadableName := mustEncryptType2Cipher(t, "moved-secret", wrongKey)
	newOrgID := testOrgID2
	newFolder := newFolderID

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{
					ID:             movedID,
					Type:           CipherTypeLogin,
					Name:           unreadableName,
					OrganizationID: &newOrgID,
					CollectionIDs:  []string{newCollectionID},
					FolderID:       &newFolder,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	old := map[string]DecryptedItem{
		movedID: {
			ID:             movedID,
			Name:           "moved-secret",
			Password:       "stale-but-present",
			OrganizationID: testOrgID,
			CollectionIDs:  []string{testCollectionID},
			FolderID:       testFolderID,
		},
		removedID: {ID: removedID, Name: "removed-item", Password: "gone"},
	}
	nameMaps := SyncNameMaps{
		Organizations: map[string]string{testOrgID: "Acme"},
		Folders:       map[string]string{testFolderID: "Prod"},
		Collections:   map[string]string{testCollectionID: "Keys"},
	}
	c := NewClient(newSyncTestClient(t, mux), time.Hour, WithState(old, nameMaps))

	if err := c.syncVault(); err == nil {
		t.Fatal("syncVault() error = nil, want the zero-decrypted sync error")
	}

	if _, err := c.GetSecret("moved-secret", SecretFilter{OrganizationIDs: []string{testOrgID}}); err == nil {
		t.Error("retained entry must not be reachable through its stale organization scope")
	}
	if _, err := c.GetSecret("moved-secret", SecretFilter{FolderID: testFolderID}); err == nil {
		t.Error("retained entry must not be reachable through its stale folder")
	}
	val, err := c.GetSecret("moved-secret", SecretFilter{
		OrganizationIDs: []string{testOrgID2},
		CollectionIDs:   []string{newCollectionID},
		FolderID:        newFolderID,
	})
	if err != nil || val != "stale-but-present" {
		t.Errorf("GetSecret() under the current scope = (%q, %v), want (stale-but-present, nil)", val, err)
	}

	if _, err := c.GetSecret("removed-item", SecretFilter{}); err == nil {
		t.Error("cipher absent from the payload must be dropped, not served from cache")
	}

	got := c.NameMaps()
	if got.Organizations[testOrgID] != "Acme" || got.Folders[testFolderID] != "Prod" || got.Collections[testCollectionID] != "Keys" {
		t.Errorf("nameMaps = %+v, want the maps from the last successful sync preserved", got)
	}
}

func TestShouldEscalateSyncFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		consecutive int
		want        bool
	}{
		{0, false},
		{1, false},
		{2, false},
		{3, true},
		{4, true},
	}
	for _, tt := range tests {
		if got := shouldEscalateSyncFailure(tt.consecutive); got != tt.want {
			t.Errorf("shouldEscalateSyncFailure(%d) = %v, want %v", tt.consecutive, got, tt.want)
		}
	}
}

func lookupTestItems() map[string]DecryptedItem {
	return map[string]DecryptedItem{
		"cipher-b": {ID: "cipher-b", Name: "api-key", Password: "beta"},
		"cipher-a": {ID: "cipher-a", Name: "API-KEY", Password: "alpha"},
		"cipher-c": {ID: "cipher-c", Name: "stripe-api-key-prod", Password: "gamma"},
	}
}

// Regression for #30: ranging over the item map made the winner depend on Go's
// randomized map iteration order, so the same request could return a different
// secret each time. Candidates are now ordered by cipher id.
func TestGetSecret_AmbiguousMatchIsDeterministic(t *testing.T) {
	t.Parallel()

	client := NewClient(nil, time.Minute, WithState(lookupTestItems(), emptySyncNameMaps()))

	for _, name := range []string{"api-key", "api"} {
		first, err := client.GetSecret(name, SecretFilter{})
		if err != nil {
			t.Fatalf("GetSecret(%q): %v", name, err)
		}
		for i := range 20 {
			got, err := client.GetSecret(name, SecretFilter{})
			if err != nil {
				t.Fatalf("GetSecret(%q) attempt %d: %v", name, i, err)
			}
			if got != first {
				t.Fatalf("GetSecret(%q) returned %q then %q; lookup is not deterministic", name, first, got)
			}
		}
		// Lowest cipher id among the matches.
		if first != "alpha" {
			t.Errorf("GetSecret(%q) = %q, want %q (cipher-a sorts first)", name, first, "alpha")
		}
	}
}

// An exact match always beats a substring match, whatever the id ordering.
func TestGetSecret_ExactMatchWinsOverSubstring(t *testing.T) {
	t.Parallel()

	items := map[string]DecryptedItem{
		"cipher-a": {ID: "cipher-a", Name: "stripe-api-key-prod", Password: "substring"},
		"cipher-z": {ID: "cipher-z", Name: "api-key", Password: "exact"},
	}
	client := NewClient(nil, time.Minute, WithState(items, emptySyncNameMaps()))

	got, err := client.GetSecret("api-key", SecretFilter{})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "exact" {
		t.Errorf("GetSecret = %q, want %q", got, "exact")
	}
}

func TestGetSecret_StrictMatchDisablesSubstringFallback(t *testing.T) {
	t.Parallel()

	items := lookupTestItems()

	strict := NewClient(nil, time.Minute, WithState(items, emptySyncNameMaps()), WithStrictMatch(true))
	if _, err := strict.GetSecret("api", SecretFilter{}); err == nil {
		t.Error("strict client resolved a substring match, want an error")
	}
	// An exact match still resolves, case-insensitively.
	if _, err := strict.GetSecret("API-key", SecretFilter{}); err != nil {
		t.Errorf("strict client rejected an exact match: %v", err)
	}

	lenient := NewClient(nil, time.Minute, WithState(items, emptySyncNameMaps()))
	if _, err := lenient.GetSecret("api", SecretFilter{}); err != nil {
		t.Errorf("default client rejected a substring match: %v", err)
	}
}

func TestGetSecret_ScopeStillAppliesToAmbiguousNames(t *testing.T) {
	t.Parallel()

	items := map[string]DecryptedItem{
		"cipher-a": {ID: "cipher-a", Name: "api-key", Password: "out-of-scope", OrganizationID: "org-other"},
		"cipher-b": {ID: "cipher-b", Name: "api-key", Password: "in-scope", OrganizationID: "org-mine"},
	}
	client := NewClient(nil, time.Minute, WithState(items, emptySyncNameMaps()))

	got, err := client.GetSecret("api-key", SecretFilter{OrganizationIDs: []string{"org-mine"}})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "in-scope" {
		t.Errorf("GetSecret = %q, want %q — cipher-a sorts first but is out of scope", got, "in-scope")
	}
}

func TestGetSecret_EmptyName(t *testing.T) {
	t.Parallel()

	client := NewClient(nil, time.Minute, WithState(lookupTestItems(), emptySyncNameMaps()))
	if _, err := client.GetSecret("", SecretFilter{}); err == nil {
		t.Error("expected an error for an empty name")
	}
}

// POST /refresh calls syncVault directly while the background ticker may be
// inside one. Both fetch, then both publish; without serialization whichever
// fetch returns last wins regardless of which snapshot is newer, so an older
// payload can resurrect items the newer one dropped.
func TestSyncVault_ConcurrentCallsAreSerialized(t *testing.T) {
	userKey := testUserKey()
	name := mustEncryptType2Cipher(t, "api-key", userKey)

	var (
		mu      sync.Mutex
		inside  int
		overlap bool
		calls   int
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inside++
		calls++
		if inside > 1 {
			overlap = true
		}
		mu.Unlock()

		time.Sleep(30 * time.Millisecond) // widen the window a racing caller would hit

		mu.Lock()
		inside--
		mu.Unlock()

		resp := SyncResponse{
			Ciphers: []SyncCipher{{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Type: CipherTypeLogin, Name: name}},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode sync response: %v", err)
		}
	})

	c := NewClient(newSyncTestClient(t, mux), time.Hour)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.syncVault(); err != nil {
				t.Errorf("syncVault: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if overlap {
		t.Error("two syncs ran concurrently; a slower one can publish a staler snapshot last")
	}
	if calls != 4 {
		t.Errorf("sync called %d times, want 4", calls)
	}
}

// The custom-field fallback used to range over a map, so an item with several
// fields resolved to a different one per request.
func TestExtractSecret_FieldFallbackIsDeterministic(t *testing.T) {
	t.Parallel()

	item := DecryptedItem{
		Fields: map[string]string{
			"zeta":  "z",
			"alpha": "a",
			"mid":   "m",
			"beta":  "b",
		},
	}

	first := extractSecret(item)
	for range 50 {
		if got := extractSecret(item); got != first {
			t.Fatalf("extractSecret returned %q then %q; field fallback is not deterministic", first, got)
		}
	}
	if first != "a" {
		t.Errorf("extractSecret = %q, want %q (lowest field name)", first, "a")
	}
}

// The named-priority fields still outrank the alphabetical fallback.
func TestExtractSecret_PriorityFieldsWinOverFallback(t *testing.T) {
	t.Parallel()

	item := DecryptedItem{
		Fields: map[string]string{
			"aaa":   "alphabetically-first",
			"token": "priority",
		},
	}
	if got := extractSecret(item); got != "priority" {
		t.Errorf("extractSecret = %q, want %q", got, "priority")
	}
}

// Stop must abandon a vault request that is already in flight. Without a
// cancellable context, shutdown waits out the 30s HTTP client timeout while the
// server sits on the connection.
func TestStop_CancelsInFlightSync(t *testing.T) {
	released := make(chan struct{})
	reached := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		close(reached)
		select {
		case <-r.Context().Done(): // client went away
		case <-released:
		}
	})

	c := NewClient(newSyncTestClient(t, mux), time.Hour)
	t.Cleanup(func() { close(released) })

	done := make(chan error, 1)
	go func() { done <- c.syncVault() }()

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("sync never reached the server")
	}

	c.Stop()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("syncVault returned nil; want the cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("syncVault error = %v, want it to wrap context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("syncVault did not return after Stop; the request was not cancelled")
	}
}

func TestStop_IsIdempotent(t *testing.T) {
	c := NewClient(nil, time.Hour)
	c.Stop()
	c.Stop() // must not panic on a second close
}

// Regression for #28: a cipher whose name decrypted but whose password did not
// used to replace a good cache entry, and the caller got HTTP 200 with an empty
// value. It must count as a failed cipher so the retain path keeps the last
// known good plaintext.
func TestSyncVault_FieldDecryptFailureRetainsLastKnownGood(t *testing.T) {
	userKey := testUserKey()
	wrongKey := testOrgKey()
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	name := mustEncryptType2Cipher(t, "DB_PASSWORD", userKey)
	password := mustEncryptType2Cipher(t, "rotated-password", wrongKey)

	// A healthy cipher alongside it, so the sync partially succeeds — the case
	// #28 describes. A vault where nothing decrypts is already refused outright.
	const healthyID = "99999999-9999-4999-8999-999999999999"
	healthyName := mustEncryptType2Cipher(t, "OTHER_SECRET", userKey)
	healthyPassword := mustEncryptType2Cipher(t, "fine", userKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{Ciphers: []SyncCipher{
			{ID: id, Type: CipherTypeLogin, Name: name, Login: &SyncLogin{Password: &password}},
			{ID: healthyID, Type: CipherTypeLogin, Name: healthyName, Login: &SyncLogin{Password: &healthyPassword}},
		}}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode: %v", err)
		}
	})

	old := map[string]DecryptedItem{id: {ID: id, Name: "DB_PASSWORD", Password: "good-cached-value"}}
	c := NewClient(newSyncTestClient(t, mux), time.Hour, WithState(old, emptySyncNameMaps()))

	if err := c.syncVault(); err != nil {
		t.Fatalf("syncVault: %v", err)
	}

	got, err := c.GetSecret("DB_PASSWORD", SecretFilter{})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got == "" {
		t.Fatal("served an empty secret; the undecryptable cipher overwrote the cached value")
	}
	if got != "good-cached-value" {
		t.Errorf("GetSecret = %q, want the retained %q", got, "good-cached-value")
	}
	if n := c.retainedCount(); n != 1 {
		t.Errorf("retainedCount = %d, want 1", n)
	}
	// The healthy cipher is unaffected.
	if got, err := c.GetSecret("OTHER_SECRET", SecretFilter{}); err != nil || got != "fine" {
		t.Errorf("healthy cipher = %q, %v; want %q, nil", got, err, "fine")
	}
}

// A linked field carries a plaintext field reference, not a cipher string, so it
// must not be mistaken for a decrypt failure and condemn the whole cipher.
func TestSyncVault_LinkedFieldIsNotADecryptFailure(t *testing.T) {
	userKey := testUserKey()
	const id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	name := mustEncryptType2Cipher(t, "APP_SECRET", userKey)
	password := mustEncryptType2Cipher(t, "still-readable", userKey)
	linkedName := mustEncryptType2Cipher(t, "linked", userKey)
	linkedValue := "100" // plaintext field reference

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{Ciphers: []SyncCipher{{
			ID: id, Type: CipherTypeLogin, Name: name,
			Login:  &SyncLogin{Password: &password},
			Fields: []SyncField{{Name: &linkedName, Value: &linkedValue, Type: FieldTypeLinked}},
		}}}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode: %v", err)
		}
	})

	c := NewClient(newSyncTestClient(t, mux), time.Hour)
	if err := c.syncVault(); err != nil {
		t.Fatalf("syncVault: %v", err)
	}
	got, err := c.GetSecret("APP_SECRET", SecretFilter{})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "still-readable" {
		t.Errorf("GetSecret = %q, want %q", got, "still-readable")
	}
	if n := c.retainedCount(); n != 0 {
		t.Errorf("retainedCount = %d, want 0 — a linked field is not a decrypt failure", n)
	}
}

// A username that will not decrypt is not served as a secret, so it must not
// condemn a cipher whose password is fine.
func TestSyncVault_UsernameFailureIsNotFatal(t *testing.T) {
	userKey := testUserKey()
	wrongKey := testOrgKey()
	const id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

	name := mustEncryptType2Cipher(t, "APP_SECRET", userKey)
	password := mustEncryptType2Cipher(t, "readable", userKey)
	username := mustEncryptType2Cipher(t, "who", wrongKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{Ciphers: []SyncCipher{{
			ID: id, Type: CipherTypeLogin, Name: name,
			Login: &SyncLogin{Password: &password, Username: &username},
		}}}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode: %v", err)
		}
	})

	c := NewClient(newSyncTestClient(t, mux), time.Hour)
	if err := c.syncVault(); err != nil {
		t.Fatalf("syncVault: %v", err)
	}
	if got, err := c.GetSecret("APP_SECRET", SecretFilter{}); err != nil || got != "readable" {
		t.Errorf("GetSecret = %q, %v; want %q, nil", got, err, "readable")
	}
}
