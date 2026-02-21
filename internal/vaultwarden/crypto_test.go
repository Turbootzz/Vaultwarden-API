package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestParseCipherString_Type2(t *testing.T) {
	// Build a known cipher string of type 2 (AES-CBC-256 + HMAC-SHA256).
	iv := make([]byte, 16)
	ct := make([]byte, 32) // 2 blocks
	mac := make([]byte, 32)
	for i := range iv {
		iv[i] = byte(i)
	}
	for i := range ct {
		ct[i] = byte(i + 16)
	}
	for i := range mac {
		mac[i] = byte(i + 48)
	}

	s := "2." + base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct) + "|" +
		base64.StdEncoding.EncodeToString(mac)

	cs, err := ParseCipherString(s)
	if err != nil {
		t.Fatalf("ParseCipherString failed: %v", err)
	}
	if cs.Type != 2 {
		t.Errorf("expected type 2, got %d", cs.Type)
	}
	if len(cs.IV) != 16 {
		t.Errorf("expected IV length 16, got %d", len(cs.IV))
	}
	if len(cs.CT) != 32 {
		t.Errorf("expected CT length 32, got %d", len(cs.CT))
	}
	if len(cs.MAC) != 32 {
		t.Errorf("expected MAC length 32, got %d", len(cs.MAC))
	}
}

func TestParseCipherString_Type0(t *testing.T) {
	iv := make([]byte, 16)
	ct := make([]byte, 32)
	s := "0." + base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct)

	cs, err := ParseCipherString(s)
	if err != nil {
		t.Fatalf("ParseCipherString failed: %v", err)
	}
	if cs.Type != 0 {
		t.Errorf("expected type 0, got %d", cs.Type)
	}
	if cs.MAC != nil {
		t.Error("expected nil MAC for type 0")
	}
}

func TestParseCipherString_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"no type", "abcdef"},
		{"bad type", "x.abc|def|ghi"},
		{"type 2 missing mac", "2.abc|def"},
		{"type 0 extra parts", "0.abc|def|ghi"},
		{"unsupported type", "5.abc|def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCipherString(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestPKCS7Unpad(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:  "1 byte padding",
			input: []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x01},
			want:  []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F},
		},
		{
			name:  "full block padding",
			input: append(make([]byte, 0), 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10),
			want:  []byte{},
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "zero padding byte",
			input:   []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkcs7Unpad(tt.input, 16)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("length mismatch: got %d, want %d", len(got), len(tt.want))
			}
		})
	}
}

func TestDecrypt_Type2_RoundTrip(t *testing.T) {
	// Create a known key, encrypt some data, then decrypt it.
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i)
	}
	for i := range macKey {
		macKey[i] = byte(i + 32)
	}
	key := SymmetricKey{EncKey: encKey, MacKey: macKey}

	plaintext := []byte("Hello, Vaultwarden!")

	// Pad the plaintext with PKCS7.
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	// Encrypt with AES-CBC.
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 100)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	// Compute MAC.
	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ct)
	macBytes := mac.Sum(nil)

	// Build cipher string.
	s := "2." + base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct) + "|" +
		base64.StdEncoding.EncodeToString(macBytes)

	cs, err := ParseCipherString(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	result, err := cs.DecryptToString(key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if result != "Hello, Vaultwarden!" {
		t.Errorf("got %q, want %q", result, "Hello, Vaultwarden!")
	}
}

func TestDecrypt_MACVerificationFails(t *testing.T) {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	key := SymmetricKey{EncKey: encKey, MacKey: macKey}

	// Create a valid ciphertext but with a wrong MAC.
	iv := make([]byte, 16)
	ct := make([]byte, 16)
	wrongMAC := make([]byte, 32)
	for i := range wrongMAC {
		wrongMAC[i] = 0xFF
	}

	s := "2." + base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct) + "|" +
		base64.StdEncoding.EncodeToString(wrongMAC)

	cs, err := ParseCipherString(s)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cs.Decrypt(key)
	if err == nil {
		t.Error("expected MAC verification error")
	}
	if !strings.Contains(err.Error(), "MAC verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMakeMasterKey_PBKDF2(t *testing.T) {
	key, err := MakeMasterKey("password123", "user@example.com", KdfPBKDF2, 600000, nil, nil)
	if err != nil {
		t.Fatalf("MakeMasterKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}

	// Verify it matches raw PBKDF2.
	expected := pbkdf2.Key([]byte("password123"), []byte("user@example.com"), 600000, 32, sha256.New)
	for i := range key {
		if key[i] != expected[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestMakeMasterKey_Argon2id(t *testing.T) {
	mem := 64
	par := 4
	key, err := MakeMasterKey("password123", "user@example.com", KdfArgon2id, 3, &mem, &par)
	if err != nil {
		t.Fatalf("MakeMasterKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
}

func TestHashPassword(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	hash := HashPassword("password123", masterKey)
	if hash == "" {
		t.Error("empty hash")
	}

	// Should be valid base64.
	_, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Errorf("hash is not valid base64: %v", err)
	}
}

func TestStretchKey(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key, err := StretchKey(masterKey)
	if err != nil {
		t.Fatalf("StretchKey failed: %v", err)
	}

	if len(key.EncKey) != 32 {
		t.Errorf("expected 32-byte enc key, got %d", len(key.EncKey))
	}
	if len(key.MacKey) != 32 {
		t.Errorf("expected 32-byte mac key, got %d", len(key.MacKey))
	}

	// Enc and Mac keys should be different.
	same := true
	for i := range key.EncKey {
		if key.EncKey[i] != key.MacKey[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("enc and mac keys should differ")
	}
}

func TestDecryptStr_Empty(t *testing.T) {
	key := SymmetricKey{EncKey: make([]byte, 32), MacKey: make([]byte, 32)}
	result, err := DecryptStr("", key)
	if err != nil {
		t.Fatalf("DecryptStr empty should not error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

// --- RSA / Organization key tests ---

func TestParseCipherString_Type3_RSA_SHA256(t *testing.T) {
	// Type 3: RSA-2048 OAEP SHA-256. Single base64 ciphertext, no IV or MAC.
	ct := make([]byte, 256) // RSA-2048 ciphertext is 256 bytes
	for i := range ct {
		ct[i] = byte(i)
	}
	s := "3." + base64.StdEncoding.EncodeToString(ct)

	cs, err := ParseCipherString(s)
	if err != nil {
		t.Fatalf("ParseCipherString type 3 failed: %v", err)
	}
	if cs.Type != EncTypeRsa2048_OaepSha256_B64 {
		t.Errorf("expected type %d, got %d", EncTypeRsa2048_OaepSha256_B64, cs.Type)
	}
	if len(cs.CT) != 256 {
		t.Errorf("expected CT length 256, got %d", len(cs.CT))
	}
	if cs.IV != nil {
		t.Error("expected nil IV for RSA type")
	}
	if cs.MAC != nil {
		t.Error("expected nil MAC for RSA type")
	}
}

func TestParseCipherString_Type4_RSA_SHA1(t *testing.T) {
	ct := make([]byte, 256)
	for i := range ct {
		ct[i] = byte(i)
	}
	s := "4." + base64.StdEncoding.EncodeToString(ct)

	cs, err := ParseCipherString(s)
	if err != nil {
		t.Fatalf("ParseCipherString type 4 failed: %v", err)
	}
	if cs.Type != EncTypeRsa2048_OaepSha1_B64 {
		t.Errorf("expected type %d, got %d", EncTypeRsa2048_OaepSha1_B64, cs.Type)
	}
	if len(cs.CT) != 256 {
		t.Errorf("expected CT length 256, got %d", len(cs.CT))
	}
}

func TestDecryptRSA_OAEP_SHA1_RoundTrip(t *testing.T) {
	// Generate RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Encrypt a 64-byte org key with RSA-OAEP SHA-1.
	orgKeyPlain := make([]byte, 64)
	for i := range orgKeyPlain {
		orgKeyPlain[i] = byte(i)
	}

	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.PublicKey, orgKeyPlain, nil)
	if err != nil {
		t.Fatalf("RSA encrypt: %v", err)
	}

	// Build cipher string type 4.
	csStr := "4." + base64.StdEncoding.EncodeToString(ciphertext)
	cs, err := ParseCipherString(csStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	decrypted, err := cs.DecryptRSA(privateKey)
	if err != nil {
		t.Fatalf("DecryptRSA: %v", err)
	}

	if len(decrypted) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(decrypted))
	}
	for i := range orgKeyPlain {
		if decrypted[i] != orgKeyPlain[i] {
			t.Fatalf("mismatch at byte %d", i)
		}
	}
}

func TestDecryptRSA_OAEP_SHA256_RoundTrip(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	plaintext := []byte("Hello RSA-OAEP-SHA256!")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("RSA encrypt: %v", err)
	}

	csStr := "3." + base64.StdEncoding.EncodeToString(ciphertext)
	cs, err := ParseCipherString(csStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	decrypted, err := cs.DecryptRSA(privateKey)
	if err != nil {
		t.Fatalf("DecryptRSA: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptRSA_WrongType(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Type 2 is AES, not RSA.
	cs := &CipherString{Type: EncTypeAesCbc256_HmacSha256_B64, CT: []byte("test")}
	_, err = cs.DecryptRSA(privateKey)
	if err == nil {
		t.Error("expected error for non-RSA type")
	}
}

func TestDecryptPrivateKey_RoundTrip(t *testing.T) {
	// Generate RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Marshal to PKCS8 DER.
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	// Encrypt with AES-CBC + HMAC (type 2) using a known symmetric key.
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i)
	}
	for i := range macKey {
		macKey[i] = byte(i + 32)
	}
	symKey := SymmetricKey{EncKey: encKey, MacKey: macKey}

	// PKCS7 pad the DER bytes.
	padLen := aes.BlockSize - (len(derBytes) % aes.BlockSize)
	padded := make([]byte, len(derBytes)+padLen)
	copy(padded, derBytes)
	for i := len(derBytes); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	// Encrypt.
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	// Compute MAC.
	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ct)
	macBytes := mac.Sum(nil)

	// Build cipher string.
	csStr := fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(macBytes),
	)

	// Decrypt and verify.
	decryptedKey, err := DecryptPrivateKey(csStr, symKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	// Verify the decrypted key matches the original.
	if decryptedKey.N.Cmp(privateKey.N) != 0 {
		t.Error("decrypted private key N mismatch")
	}
	if decryptedKey.D.Cmp(privateKey.D) != 0 {
		t.Error("decrypted private key D mismatch")
	}
}

func TestDecryptPrivateKey_Empty(t *testing.T) {
	symKey := SymmetricKey{EncKey: make([]byte, 32), MacKey: make([]byte, 32)}
	_, err := DecryptPrivateKey("", symKey)
	if err == nil {
		t.Error("expected error for empty private key")
	}
}

func TestDecryptOrgKey_RoundTrip(t *testing.T) {
	// Generate RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Create a 64-byte org key (32 enc + 32 mac).
	orgKeyPlain := make([]byte, 64)
	for i := 0; i < 32; i++ {
		orgKeyPlain[i] = byte(i)      // encKey
		orgKeyPlain[32+i] = byte(i + 64) // macKey
	}

	// Encrypt with RSA-OAEP SHA-1 (type 4).
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.PublicKey, orgKeyPlain, nil)
	if err != nil {
		t.Fatalf("RSA encrypt: %v", err)
	}

	csStr := "4." + base64.StdEncoding.EncodeToString(ciphertext)

	// Decrypt.
	orgKey, err := DecryptOrgKey(csStr, privateKey)
	if err != nil {
		t.Fatalf("DecryptOrgKey: %v", err)
	}

	// Verify encKey.
	for i := 0; i < 32; i++ {
		if orgKey.EncKey[i] != byte(i) {
			t.Fatalf("encKey mismatch at byte %d", i)
		}
	}

	// Verify macKey.
	for i := 0; i < 32; i++ {
		if orgKey.MacKey[i] != byte(i+64) {
			t.Fatalf("macKey mismatch at byte %d", i)
		}
	}
}

func TestDecryptOrgKey_Empty(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := DecryptOrgKey("", privateKey)
	if err == nil {
		t.Error("expected error for empty org key")
	}
}

func TestDecryptOrgKey_WrongLength(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Encrypt a 32-byte value (should be 64).
	plaintext := make([]byte, 32)
	ct, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.PublicKey, plaintext, nil)
	csStr := "4." + base64.StdEncoding.EncodeToString(ct)

	_, err := DecryptOrgKey(csStr, privateKey)
	if err == nil {
		t.Error("expected error for wrong org key length")
	}
	if !strings.Contains(err.Error(), "unexpected org key length") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecryptCipher_WithOrgKey(t *testing.T) {
	// Create two different symmetric keys: personal and org.
	personalKey := SymmetricKey{
		EncKey: make([]byte, 32),
		MacKey: make([]byte, 32),
	}
	orgKey := SymmetricKey{
		EncKey: make([]byte, 32),
		MacKey: make([]byte, 32),
	}
	for i := range orgKey.EncKey {
		orgKey.EncKey[i] = byte(i + 100)
	}
	for i := range orgKey.MacKey {
		orgKey.MacKey[i] = byte(i + 132)
	}

	// Encrypt a cipher name with the org key.
	plainName := []byte("ORG_SECRET")
	padLen := aes.BlockSize - (len(plainName) % aes.BlockSize)
	padded := make([]byte, len(plainName)+padLen)
	copy(padded, plainName)
	for i := len(plainName); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 50)
	}

	block, _ := aes.NewCipher(orgKey.EncKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, orgKey.MacKey)
	mac.Write(iv)
	mac.Write(ct)
	macBytes := mac.Sum(nil)

	encryptedName := fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(macBytes),
	)

	orgID := "org-123"
	cipher := SyncCipher{
		ID:             "cipher-1",
		Type:           CipherTypeLogin,
		OrganizationID: &orgID,
		Name:           encryptedName,
	}

	// Should fail with personal key (MAC mismatch).
	_, err := decryptCipher(cipher, personalKey)
	if err == nil {
		t.Error("expected error when decrypting org cipher with personal key")
	}

	// Should succeed with org key.
	item, err := decryptCipher(cipher, orgKey)
	if err != nil {
		t.Fatalf("decryptCipher with org key failed: %v", err)
	}
	if item.Name != "ORG_SECRET" {
		t.Errorf("got name %q, want %q", item.Name, "ORG_SECRET")
	}
}

func TestDecryptCipher_PersonalItemStillWorks(t *testing.T) {
	// Verify backward compatibility: personal items with no orgID decrypt with personal key.
	key := SymmetricKey{
		EncKey: make([]byte, 32),
		MacKey: make([]byte, 32),
	}
	for i := range key.EncKey {
		key.EncKey[i] = byte(i)
	}
	for i := range key.MacKey {
		key.MacKey[i] = byte(i + 32)
	}

	plainName := []byte("PERSONAL_SECRET")
	padLen := aes.BlockSize - (len(plainName) % aes.BlockSize)
	padded := make([]byte, len(plainName)+padLen)
	copy(padded, plainName)
	for i := len(plainName); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, 16)
	block, _ := aes.NewCipher(key.EncKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, key.MacKey)
	mac.Write(iv)
	mac.Write(ct)
	macBytes := mac.Sum(nil)

	encryptedName := fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(macBytes),
	)

	// No organizationId — personal item.
	c := SyncCipher{
		ID:   "personal-1",
		Type: CipherTypeSecureNote,
		Name: encryptedName,
	}

	item, err := decryptCipher(c, key)
	if err != nil {
		t.Fatalf("decryptCipher personal item failed: %v", err)
	}
	if item.Name != "PERSONAL_SECRET" {
		t.Errorf("got name %q, want %q", item.Name, "PERSONAL_SECRET")
	}
}
