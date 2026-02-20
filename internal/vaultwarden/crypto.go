// Package vaultwarden provides native Bitwarden-compatible encryption and decryption.
// This replaces the Bitwarden CLI dependency with pure Go crypto.
package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Encryption types as defined by the Bitwarden protocol.
const (
	EncTypeAesCbc256_B64              = 0
	EncTypeAesCbc128_HmacSha256_B64   = 1
	EncTypeAesCbc256_HmacSha256_B64   = 2
	EncTypeRsa2048_OaepSha256_B64     = 3
	EncTypeRsa2048_OaepSha1_B64       = 4
)

// KDF types.
const (
	KdfPBKDF2   = 0
	KdfArgon2id = 1
)

// SymmetricKey holds the encryption and MAC keys for AES-CBC + HMAC-SHA256.
type SymmetricKey struct {
	EncKey []byte // 32 bytes for AES-256
	MacKey []byte // 32 bytes for HMAC-SHA256
}

// CipherString represents an encrypted Bitwarden value.
// Format: "<encType>.<iv>|<ciphertext>|<mac>"
type CipherString struct {
	Type int
	IV   []byte
	CT   []byte
	MAC  []byte
}

// ParseCipherString parses a Bitwarden encrypted string.
func ParseCipherString(s string) (*CipherString, error) {
	if s == "" {
		return nil, errors.New("empty cipher string")
	}

	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cipher string: missing type separator")
	}

	encType, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid encryption type: %w", err)
	}

	cs := &CipherString{Type: encType}
	pieces := strings.Split(parts[1], "|")

	switch encType {
	case EncTypeAesCbc256_B64:
		if len(pieces) != 2 {
			return nil, fmt.Errorf("AesCbc256_B64 expects 2 parts, got %d", len(pieces))
		}
		if cs.IV, err = base64.StdEncoding.DecodeString(pieces[0]); err != nil {
			return nil, fmt.Errorf("invalid IV: %w", err)
		}
		if cs.CT, err = base64.StdEncoding.DecodeString(pieces[1]); err != nil {
			return nil, fmt.Errorf("invalid ciphertext: %w", err)
		}

	case EncTypeAesCbc256_HmacSha256_B64:
		if len(pieces) != 3 {
			return nil, fmt.Errorf("AesCbc256_HmacSha256_B64 expects 3 parts, got %d", len(pieces))
		}
		if cs.IV, err = base64.StdEncoding.DecodeString(pieces[0]); err != nil {
			return nil, fmt.Errorf("invalid IV: %w", err)
		}
		if cs.CT, err = base64.StdEncoding.DecodeString(pieces[1]); err != nil {
			return nil, fmt.Errorf("invalid ciphertext: %w", err)
		}
		if cs.MAC, err = base64.StdEncoding.DecodeString(pieces[2]); err != nil {
			return nil, fmt.Errorf("invalid MAC: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported encryption type: %d", encType)
	}

	return cs, nil
}

// Decrypt decrypts a CipherString using the provided symmetric key.
func (cs *CipherString) Decrypt(key SymmetricKey) ([]byte, error) {
	if len(cs.IV) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: %d", len(cs.IV))
	}
	if len(cs.CT) == 0 || len(cs.CT)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(cs.CT))
	}

	// Verify MAC if present (type 2).
	if cs.Type == EncTypeAesCbc256_HmacSha256_B64 {
		if len(key.MacKey) == 0 {
			return nil, errors.New("MAC key required for type 2 decryption")
		}
		mac := hmac.New(sha256.New, key.MacKey)
		mac.Write(cs.IV)
		mac.Write(cs.CT)
		expectedMAC := mac.Sum(nil)
		if !hmac.Equal(expectedMAC, cs.MAC) {
			return nil, errors.New("MAC verification failed")
		}
	}

	// AES-CBC decrypt.
	block, err := aes.NewCipher(key.EncKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	plaintext := make([]byte, len(cs.CT))
	mode := cipher.NewCBCDecrypter(block, cs.IV)
	mode.CryptBlocks(plaintext, cs.CT)

	// Remove PKCS7 padding.
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("pkcs7 unpad: %w", err)
	}

	return plaintext, nil
}

// DecryptToString decrypts and returns the plaintext as a string.
func (cs *CipherString) DecryptToString(key SymmetricKey) (string, error) {
	b, err := cs.Decrypt(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecryptStr is a convenience function to parse and decrypt a cipher string in one call.
func DecryptStr(s string, key SymmetricKey) (string, error) {
	if s == "" {
		return "", nil
	}
	cs, err := ParseCipherString(s)
	if err != nil {
		return "", err
	}
	return cs.DecryptToString(key)
}

// MakeMasterKey derives the master key from the user's password and email.
func MakeMasterKey(password, email string, kdfType, iterations int, memory, parallelism *int) ([]byte, error) {
	salt := []byte(strings.ToLower(strings.TrimSpace(email)))

	switch kdfType {
	case KdfPBKDF2:
		if iterations < 1 {
			return nil, fmt.Errorf("PBKDF2 iterations must be >= 1, got %d", iterations)
		}
		return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New), nil

	case KdfArgon2id:
		mem := 64 * 1024 // default 64 MiB
		par := 4         // default parallelism
		if memory != nil {
			mem = *memory * 1024 // API returns MiB, argon2 wants KiB
		}
		if parallelism != nil {
			par = *parallelism
		}
		return argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(mem), uint8(par), 32), nil

	default:
		return nil, fmt.Errorf("unsupported KDF type: %d", kdfType)
	}
}

// HashPassword creates the password hash for authentication.
// hash = Base64(PBKDF2(masterKey, password, 1, 32, SHA256))
func HashPassword(password string, masterKey []byte) string {
	hash := pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// StretchKey expands a 32-byte master key into a 64-byte stretched key
// using HKDF-Expand with SHA-256. Returns (encKey, macKey).
func StretchKey(masterKey []byte) (SymmetricKey, error) {
	encKey := make([]byte, 32)
	r := hkdf.Expand(sha256.New, masterKey, []byte("enc"))
	if _, err := io.ReadFull(r, encKey); err != nil {
		return SymmetricKey{}, fmt.Errorf("hkdf expand enc: %w", err)
	}

	macKey := make([]byte, 32)
	r = hkdf.Expand(sha256.New, masterKey, []byte("mac"))
	if _, err := io.ReadFull(r, macKey); err != nil {
		return SymmetricKey{}, fmt.Errorf("hkdf expand mac: %w", err)
	}

	return SymmetricKey{EncKey: encKey, MacKey: macKey}, nil
}

// DecryptSymmetricKey decrypts the user's encrypted symmetric key from the login response.
// It tries HKDF-stretched key first, then falls back to legacy (unstretched) key.
func DecryptSymmetricKey(encryptedKey string, masterKey []byte) (SymmetricKey, error) {
	cs, err := ParseCipherString(encryptedKey)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("parse encrypted key: %w", err)
	}

	// Try modern approach: HKDF-stretched key.
	stretched, err := StretchKey(masterKey)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("stretch key: %w", err)
	}

	decrypted, err := cs.Decrypt(stretched)
	if err != nil {
		// Fallback: legacy mode (master key used directly as enc key, no MAC).
		legacy := SymmetricKey{EncKey: masterKey}
		decrypted, err = cs.Decrypt(legacy)
		if err != nil {
			return SymmetricKey{}, fmt.Errorf("decrypt symmetric key (tried stretched + legacy): %w", err)
		}
	}

	// The decrypted key is 64 bytes: first 32 = encKey, last 32 = macKey.
	if len(decrypted) != 64 {
		return SymmetricKey{}, fmt.Errorf("unexpected symmetric key length: %d (expected 64)", len(decrypted))
	}

	return SymmetricKey{
		EncKey: decrypted[:32],
		MacKey: decrypted[32:],
	}, nil
}

// pkcs7Unpad removes PKCS#7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("data not block-aligned")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("invalid padding length: %d", padLen)
	}

	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return data[:len(data)-padLen], nil
}
