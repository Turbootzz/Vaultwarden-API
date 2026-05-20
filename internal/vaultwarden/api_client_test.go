package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
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
	data := []byte(plaintext)
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
