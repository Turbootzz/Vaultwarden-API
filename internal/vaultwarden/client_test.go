package vaultwarden

import (
	"strings"
	"testing"
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

	c := NewClient(nil, 0, 0, WithState(items, nameMaps))

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
