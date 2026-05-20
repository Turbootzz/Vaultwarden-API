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
				FolderID:         testFolderID,
			},
			true,
		},
		{
			"org ok collection fail",
			SecretFilter{OrganizationID: testOrgID, CollectionID: "77777777-7777-4777-8777-777777777777"},
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
