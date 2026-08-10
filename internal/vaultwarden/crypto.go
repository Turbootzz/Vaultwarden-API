// Package vaultwarden provides native Bitwarden-compatible encryption and decryption.
// This replaces the Bitwarden CLI dependency with pure Go crypto.
package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Encryption types as defined by the Bitwarden protocol.
const (
	EncTypeAesCbc256_B64            = 0
	EncTypeAesCbc128_HmacSha256_B64 = 1
	EncTypeAesCbc256_HmacSha256_B64 = 2
	EncTypeRsa2048_OaepSha256_B64   = 3
	EncTypeRsa2048_OaepSha1_B64     = 4
)

// KDF types.
const (
	KdfPBKDF2   = 0
	KdfArgon2id = 1
)

// Accepted bounds for server-supplied Argon2id parameters.
//
// These are operational limits, not merely the points at which the conversion
// to argon2's uint32 arguments would overflow. The parameters arrive in the
// server's prelogin response, and deriving the key allocates memory MiB and
// spends iterations passes over it — so a hostile or misconfigured server
// otherwise dictates how much of this process's memory and CPU to burn, in a
// container that docker-compose caps at 128 MiB.
//
// The ceilings sit an order of magnitude above what Bitwarden and Vaultwarden
// clients can actually configure (memory 16-1024 MiB, parallelism 1-16,
// iterations 2-10), so a legitimate server is never rejected.
const (
	argon2MaxMemoryMiB   = 1024
	argon2MaxParallelism = 64
	argon2MaxIterations  = 100
)

// Floors for the same parameters. Without them the server chooses how weak the
// derivation is, and the password hash sent to it is derived from the master key
// — so a server answering prelogin with one PBKDF2 iteration receives a hash it
// can brute-force back to the master password offline. Official clients enforce
// the same floors, so a legitimate account always clears them.
const (
	pbkdf2MinIterations = 5000
	// Below this a PBKDF2 account is weaker than every current default and worth
	// flagging, but it is still a valid configuration, so it is not rejected.
	pbkdf2WarnIterations = 100000
	argon2MinMemoryMiB   = 16
)

// SymmetricKey holds the encryption and MAC keys for AES-CBC + HMAC-SHA256.
type SymmetricKey struct {
	EncKey []byte // 32 bytes for AES-256
	MacKey []byte // 32 bytes for HMAC-SHA256
}

// CipherString represents an encrypted Bitwarden value.
// Format for AES types: "<encType>.<iv>|<ciphertext>|<mac>"
// Format for RSA types: "<encType>.<ciphertext>"
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

	case EncTypeRsa2048_OaepSha256_B64, EncTypeRsa2048_OaepSha1_B64:
		// RSA types: single base64-encoded ciphertext, no IV or MAC.
		raw := strings.Join(pieces, "|") // rejoin in case base64 contained no pipes
		if cs.CT, err = base64.StdEncoding.DecodeString(raw); err != nil {
			return nil, fmt.Errorf("invalid RSA ciphertext: %w", err)
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

	// A key carrying a MAC key belongs to a MAC'd encryption type. Accepting an
	// unauthenticated type 0 value under such a key would let whoever serves the
	// payload strip integrity protection by relabelling the cipher string, so
	// type 0 is only honoured for legacy keys that have no MAC key at all.
	if cs.Type == EncTypeAesCbc256_B64 && len(key.MacKey) > 0 {
		return nil, errors.New("refusing unauthenticated type 0 cipher string under a MAC-carrying key")
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
		if iterations < pbkdf2MinIterations {
			return nil, fmt.Errorf(
				"PBKDF2 iterations must be >= %d, got %d (refusing to derive a key the server can trivially reverse)",
				pbkdf2MinIterations, iterations)
		}
		if iterations < pbkdf2WarnIterations {
			logger.Warn.Printf(
				"Vaultwarden reports only %d PBKDF2 iterations; raise the account KDF setting (current default is 600000)",
				iterations)
		}
		return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New), nil

	case KdfArgon2id:
		// The KDF parameters come from the server's prelogin response. argon2
		// panics on out-of-range values and the memory conversion overflows, so
		// they are bounds-checked here and reported as errors (#31).
		if iterations < 1 || iterations > argon2MaxIterations {
			return nil, fmt.Errorf("Argon2id iterations must be between 1 and %d, got %d", argon2MaxIterations, iterations)
		}
		mem := 64 * 1024 // default 64 MiB
		par := 4         // default parallelism
		if memory != nil {
			if *memory < argon2MinMemoryMiB || *memory > argon2MaxMemoryMiB {
				return nil, fmt.Errorf("Argon2id memory must be between %d and %d MiB, got %d", argon2MinMemoryMiB, argon2MaxMemoryMiB, *memory)
			}
			mem = *memory * 1024 // API returns MiB, argon2 wants KiB
		}
		if parallelism != nil {
			if *parallelism < 1 || *parallelism > argon2MaxParallelism {
				return nil, fmt.Errorf("Argon2id parallelism must be between 1 and %d, got %d", argon2MaxParallelism, *parallelism)
			}
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

// DecryptRSA decrypts a CipherString using an RSA private key (OAEP).
// Supports type 3 (SHA-256) and type 4 (SHA-1).
func (cs *CipherString) DecryptRSA(privateKey *rsa.PrivateKey) ([]byte, error) {
	switch cs.Type {
	case EncTypeRsa2048_OaepSha256_B64:
		return rsa.DecryptOAEP(sha256.New(), nil, privateKey, cs.CT, nil)
	case EncTypeRsa2048_OaepSha1_B64:
		return rsa.DecryptOAEP(sha1.New(), nil, privateKey, cs.CT, nil)
	default:
		return nil, fmt.Errorf("not an RSA cipher type: %d", cs.Type)
	}
}

// DecryptPrivateKey decrypts the user's encrypted RSA private key from the sync response.
// The private key is AES-CBC encrypted with the user's symmetric key.
// When decrypted, it's a PKCS8 DER-encoded RSA private key.
func DecryptPrivateKey(encryptedPrivateKey string, symKey SymmetricKey) (*rsa.PrivateKey, error) {
	if encryptedPrivateKey == "" {
		return nil, errors.New("encrypted private key is empty")
	}

	cs, err := ParseCipherString(encryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key cipher string: %w", err)
	}

	derBytes, err := cs.Decrypt(symKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return rsaKey, nil
}

// DecryptOrgKey decrypts an organization's symmetric key using the user's RSA private key.
// The org key is RSA-OAEP encrypted. When decrypted, it's 64 bytes: encKey(32) + macKey(32).
func DecryptOrgKey(encryptedOrgKey string, privateKey *rsa.PrivateKey) (SymmetricKey, error) {
	if encryptedOrgKey == "" {
		return SymmetricKey{}, errors.New("encrypted org key is empty")
	}

	cs, err := ParseCipherString(encryptedOrgKey)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("parse org key cipher string: %w", err)
	}

	decrypted, err := cs.DecryptRSA(privateKey)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("RSA decrypt org key: %w", err)
	}

	if len(decrypted) != 64 {
		return SymmetricKey{}, fmt.Errorf("unexpected org key length: %d (expected 64)", len(decrypted))
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
