package encrypt_test

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"appliedcryptography-starter-kit/internal/encrypt"
)

func ExampleGenerateKey() {
	// Generate a 256-bit (32-byte) key for AES-256
	key, err := encrypt.GenerateKey(32)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Generated key length: %d bytes\n", len(key))
	fmt.Printf("Key is random: %v\n", len(key) == 32)
	// Output:
	// Generated key length: 32 bytes
	// Key is random: true
}

func ExampleEncryptAESCTR() {
	// Use a fixed key and IV for example (in practice, use GenerateKey and GenerateNonce)
	key := []byte("my-32-byte-super-secret-key!!!!!") // 32 bytes for AES-256
	iv := []byte("16-byte-IV!!!!!!")                  // 16 bytes

	plaintext := []byte("Hello, this is a secret message!")

	// Encrypt
	ciphertext, err := encrypt.EncryptAESCTR(key, iv, plaintext)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	fmt.Printf("Plaintext:  %s\n", plaintext)
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	decrypted, err := encrypt.DecryptAESCTR(key, iv, ciphertext)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}

	fmt.Printf("Decrypted:  %s\n", decrypted)
	fmt.Printf("Match: %v\n", bytes.Equal(plaintext, decrypted))
	// Output:
	// Plaintext:  Hello, this is a secret message!
	// Ciphertext: 9c7ebfac9371529d8a0bc0336594349c5f994495f9cd6952ebf0a518717cb90f
	// Decrypted:  Hello, this is a secret message!
	// Match: true
}

func ExampleEncryptAESGCM() {
	// Use a fixed key and nonce for example
	key := []byte("my-32-byte-super-secret-key!!!!!") // 32 bytes for AES-256
	nonce := []byte("12-byte-nonc")                   // 12 bytes for GCM

	// Additional Authenticated Data (AAD) - this is authenticated but not encrypted
	aad := []byte("user-id:12345,timestamp:2024-01-01")
	plaintext := []byte("Secret message content")

	// Encrypt with AAD
	ciphertext, err := encrypt.EncryptAESGCM(key, nonce, plaintext, aad)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	fmt.Printf("AAD: %s\n", aad)
	fmt.Printf("Plaintext: %s\n", plaintext)

	// Decrypt with correct AAD
	decrypted, err := encrypt.DecryptAESGCM(key, nonce, ciphertext, aad)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}
	fmt.Printf("Decrypted with correct AAD: %s\n", decrypted)

	// Try to decrypt with wrong AAD (authentication will fail)
	wrongAAD := []byte("user-id:99999,timestamp:2024-01-01")
	_, err = encrypt.DecryptAESGCM(key, nonce, ciphertext, wrongAAD)
	fmt.Printf("Wrong AAD causes error: %v\n", err != nil)

	// Output:
	// AAD: user-id:12345,timestamp:2024-01-01
	// Plaintext: Secret message content
	// Decrypted with correct AAD: Secret message content
	// Wrong AAD causes error: true
}

func ExampleGenerateNonce() {
	// Generate a 12-byte nonce for AES-GCM
	gcmNonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("GCM nonce length: %d bytes\n", len(gcmNonce))

	// Generate a 16-byte IV for AES-CTR
	ctrIV, err := encrypt.GenerateNonce(16)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("CTR IV length: %d bytes\n", len(ctrIV))

	// Output:
	// GCM nonce length: 12 bytes
	// CTR IV length: 16 bytes
}

// CompleteWorkflow demonstrates a complete encryption workflow
func CompleteWorkflow() {
	// Step 1: Generate a random key
	key, err := encrypt.GenerateKey(32) // AES-256
	if err != nil {
		fmt.Printf("Key generation error: %v\n", err)
		return
	}

	// Step 2: Generate a random nonce
	nonce, err := encrypt.GenerateNonce(12) // For GCM
	if err != nil {
		fmt.Printf("Nonce generation error: %v\n", err)
		return
	}

	// Step 3: Prepare data
	message := []byte("This is a confidential message")
	metadata := []byte("sender:alice,recipient:bob")

	// Step 4: Encrypt with AAD
	ciphertext, err := encrypt.EncryptAESGCM(key, nonce, message, metadata)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	// Step 5: Decrypt
	decrypted, err := encrypt.DecryptAESGCM(key, nonce, ciphertext, metadata)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}

	fmt.Printf("Original:  %s\n", message)
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Success: %v\n", bytes.Equal(message, decrypted))
	// Output:
	// Original:  This is a confidential message
	// Decrypted: This is a confidential message
	// Success: true
}
