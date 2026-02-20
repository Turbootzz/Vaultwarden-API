package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
