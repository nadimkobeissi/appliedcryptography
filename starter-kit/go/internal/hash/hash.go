// Package hash provides simple, secure hashing functions for educational purposes.
// It includes SHA-2 (SHA-256, SHA-512) and BLAKE2b implementations.
package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/scrypt"
)

// SHA256 computes the SHA-256 hash of the input data.
// Returns a 32-byte hash.
func SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// SHA512 computes the SHA-512 hash of the input data.
// Returns a 64-byte hash.
func SHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// BLAKE2b256 computes a 256-bit BLAKE2b hash of the input data.
// This is faster than SHA-256 while being equally secure.
func BLAKE2b256(data []byte) ([]byte, error) {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLAKE2b hasher: %w", err)
	}
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

// BLAKE2b512 computes a 512-bit BLAKE2b hash of the input data.
// This is faster than SHA-512 while being equally secure.
func BLAKE2b512(data []byte) ([]byte, error) {
	hasher, err := blake2b.New512(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLAKE2b hasher: %w", err)
	}
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

// HMAC uses BLAKE2b's built-in keyed hashing mode to create a MAC (Message Authentication Code).
// The key must be between 1 and 64 bytes long.
// Returns a 64-byte MAC.
func HMAC(key, data []byte) ([]byte, error) {
	// Validate key length
	if len(key) == 0 {
		return nil, errors.New("key cannot be empty")
	}
	if len(key) > 64 {
		return nil, errors.New("key cannot be longer than 64 bytes")
	}

	// BLAKE2b supports keyed hashing natively, which can be used like HMAC
	hasher, err := blake2b.New256(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyed BLAKE2b hasher: %w", err)
	}

	hasher.Write(data)
	return hasher.Sum(nil), nil
}

// VerifyMAC checks if the provided MAC matches the expected MAC for the given key and data.
// Returns true if the MACs match, false otherwise.
func VerifyMAC(key, data, expectedMAC []byte) (bool, error) {
	computedMAC, err := HMAC(key, data)
	if err != nil {
		return false, err
	}

	// Use subtle.ConstantTimeCompare for constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(computedMAC, expectedMAC) == 1, nil
}

// Scrypt derives a key from the provided password and salt using the scrypt KDF.
// The parameters N (memory cost), r (block size), and p (parallelization) control the work factor.
// The keyLen specifies the length of the derived key (in bytes).
// Returns a key of length keyLen.
// Typical secure values are N>=32768 (2^15), r=8, p=1, with a unique 16+ byte salt.
func Scrypt(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, errors.New("keyLen must be positive")
	}
	// Delegate parameter validation to scrypt.Key as well; it returns descriptive errors
	dk, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}
	return dk, nil
}

// ScryptDefault is just Scrypt with default parameters (for ease of use).
// Defaults: N=32768, r=8, p=1. These are suitable for many applications but may be slow on constrained systems. Always use a unique, random salt.(can be changed if you find the values not suitable)
// Returns a 32-byte key.
func ScryptDefault(password, salt []byte) ([]byte, error) {
	const (
		defaultN   = 32768
		defaultr   = 8
		defaultp   = 1
		defaultLen = 32
	)
	return Scrypt(password, salt, defaultN, defaultr, defaultp, defaultLen)
}
