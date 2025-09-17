// Package dh provides simple, secure Diffie-Hellman key agreement using X25519.
// This implementation is designed for educational purposes to demonstrate
// how two parties can establish a shared secret over an insecure channel.
package dh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// PrivateKeySize is the size of an X25519 private key in bytes
	PrivateKeySize = 32
	// PublicKeySize is the size of an X25519 public key in bytes
	PublicKeySize = 32
	// SharedSecretSize is the size of the computed shared secret in bytes
	SharedSecretSize = 32
)

// KeyPair represents a Diffie-Hellman key pair
type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GeneratePrivateKey generates a random X25519 private key.
// This is a convenience function when you only need the private key.
func GeneratePrivateKey() ([]byte, error) {
	privateKey := make([]byte, PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Clamp the private key
	// https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	return privateKey, nil
}

// GenerateKeyPair generates a new X25519 key pair for Diffie-Hellman key agreement.
// The private key is a random 32-byte value, and the public key is derived from it.
func GenerateKeyPair() (*KeyPair, error) {
	// Generate random private key using the GeneratePrivateKey function
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	// Derive public key from private key
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ComputeSharedSecret computes the shared secret using our private key and their public key.
// Both parties will arrive at the same shared secret when they exchange public keys.
func ComputeSharedSecret(ourPrivateKey, theirPublicKey []byte) ([]byte, error) {
	// Validate input sizes
	if len(ourPrivateKey) != PrivateKeySize {
		return nil, errors.New("private key must be 32 bytes")
	}
	if len(theirPublicKey) != PublicKeySize {
		return nil, errors.New("public key must be 32 bytes")
	}

	// Compute shared secret using X25519
	sharedSecret, err := curve25519.X25519(ourPrivateKey, theirPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	return sharedSecret, nil
}

// DerivePublicKey derives the public key from a private key.
func DerivePublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, errors.New("private key must be 32 bytes")
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	return publicKey, nil
}
