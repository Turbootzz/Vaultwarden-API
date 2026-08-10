package vaultwarden

import (
	"encoding/json"
	"maps"
	"net/http"
	"strings"
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
	)

	freshName := mustEncryptType2Cipher(t, "api-key-v2", userKey)
	unreadableName := mustEncryptType2Cipher(t, "org-secret", wrongKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		resp := SyncResponse{
			Ciphers: []SyncCipher{
				{ID: updatedID, Type: CipherTypeLogin, Name: freshName},
				{ID: failedID, Type: CipherTypeLogin, Name: unreadableName},
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
