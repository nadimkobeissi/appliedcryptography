// Package encrypt provides simple, secure encryption functions for educational purposes.
// It includes AES-CTR (stream cipher) and AES-GCM (authenticated encryption) implementations.
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// GenerateKey generates a cryptographically secure random key.
// keySize must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
func GenerateKey(keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("key size must be 16, 24, or 32 bytes")
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	return key, nil
}

// GenerateNonce generates a cryptographically secure random nonce.
// For AES-GCM, this should be 12 bytes. For AES-CTR, this should be 16 bytes (IV).
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return nonce, nil
}

// EncryptAESCTR encrypts plaintext using AES in Counter (CTR) mode.
// CTR mode converts AES into a stream cipher.
// Note: CTR mode provides confidentiality but NOT authentication.
// The IV (initialization vector) must be 16 bytes and should be unique for each encryption.
func EncryptAESCTR(key, iv, plaintext []byte) ([]byte, error) {
	// Validate inputs
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes")
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create CTR mode
	stream := cipher.NewCTR(block, iv)

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

// DecryptAESCTR decrypts ciphertext using AES in Counter (CTR) mode.
// In CTR mode, decryption is the same operation as encryption.
func DecryptAESCTR(key, iv, ciphertext []byte) ([]byte, error) {
	// CTR mode decryption is identical to encryption
	return EncryptAESCTR(key, iv, ciphertext)
}

// EncryptAESGCM encrypts plaintext using AES in Galois/Counter Mode (GCM).
// GCM provides both confidentiality and authentication.
// The nonce should be 12 bytes and must be unique for each encryption with the same key.
// Returns the ciphertext with the authentication tag appended.
func EncryptAESGCM(key, nonce, plaintext []byte, additionalData []byte) ([]byte, error) {
	// Validate key
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes for GCM")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, additionalData)

	return ciphertext, nil
}

// DecryptAESGCM decrypts ciphertext using AES in Galois/Counter Mode (GCM).
// The ciphertext must include the authentication tag (appended by EncryptAESGCM).
// Returns an error if the authentication tag verification fails.
func DecryptAESGCM(key, nonce, ciphertext []byte, additionalData []byte) ([]byte, error) {
	// Validate key
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes for GCM")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication tag verification failed): %w", err)
	}

	return plaintext, nil
}
