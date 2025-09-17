// Package sign provides simple, secure digital signature functions using Ed25519.
// This implementation is designed for educational purposes to demonstrate
// how to create and verify digital signatures for message authentication.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// PrivateKeySize is the size of an Ed25519 private key in bytes
	PrivateKeySize = ed25519.PrivateKeySize
	// PublicKeySize is the size of an Ed25519 public key in bytes
	PublicKeySize = ed25519.PublicKeySize
	// SignatureSize is the size of an Ed25519 signature in bytes
	SignatureSize = ed25519.SignatureSize
	// SeedSize is the size of the private key seed
	SeedSize = ed25519.SeedSize
)

// KeyPair represents an Ed25519 key pair for digital signatures
type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateKeyPair generates a new Ed25519 key pair for digital signatures.
// The private key can be used to sign messages, and the public key can be
// used to verify signatures.
func GenerateKeyPair() (*KeyPair, error) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// Sign creates a digital signature for the given message using the private key.
// The signature can be verified by anyone who has the corresponding public key.
func Sign(privateKey, message []byte) ([]byte, error) {
	// Validate private key size
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes", PrivateKeySize)
	}

	// Create signature
	signature := ed25519.Sign(privateKey, message)

	return signature, nil
}

// Verify checks if the signature is valid for the given message and public key.
// Returns true if the signature is valid, false otherwise.
func Verify(publicKey, message, signature []byte) (bool, error) {
	// Validate public key size
	if len(publicKey) != PublicKeySize {
		return false, fmt.Errorf("public key must be %d bytes", PublicKeySize)
	}

	// Validate signature size
	if len(signature) != SignatureSize {
		return false, fmt.Errorf("signature must be %d bytes", SignatureSize)
	}

	// Verify signature
	valid := ed25519.Verify(publicKey, message, signature)

	return valid, nil
}

// GeneratePrivateKey generates a new Ed25519 private key.
// This is a convenience function when you only need the private key.
func GeneratePrivateKey() ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return privateKey, nil
}

// DerivePublicKey derives the public key from a private key.
func DerivePublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes", PrivateKeySize)
	}

	// Extract public key from private key
	// Ed25519 private keys contain the public key in the last 32 bytes
	publicKey := privateKey[32:]

	return publicKey, nil
}

// GenerateKeyPairFromSeed generates a deterministic key pair from a seed.
// The same seed will always produce the same key pair.
// The seed must be 32 bytes.
func GenerateKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes", SeedSize)
	}

	// Generate deterministic key pair from seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// GetSeed extracts the seed from a private key.
// The seed can be used to regenerate the same key pair.
func GetSeed(privateKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	// The first 32 bytes of an Ed25519 private key is the seed
	seed := privateKey[:SeedSize]
	return seed, nil
}
