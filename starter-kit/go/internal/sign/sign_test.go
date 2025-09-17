package sign

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	// Generate multiple key pairs and verify they're different
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Check key sizes
	if len(kp1.PrivateKey) != PrivateKeySize {
		t.Errorf("Private key size = %d, want %d", len(kp1.PrivateKey), PrivateKeySize)
	}
	if len(kp1.PublicKey) != PublicKeySize {
		t.Errorf("Public key size = %d, want %d", len(kp1.PublicKey), PublicKeySize)
	}

	// Generate another key pair
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() second call error = %v", err)
	}

	// Verify keys are different (randomness check)
	if bytes.Equal(kp1.PrivateKey, kp2.PrivateKey) {
		t.Error("Generated identical private keys (not random)")
	}
	if bytes.Equal(kp1.PublicKey, kp2.PublicKey) {
		t.Error("Generated identical public keys (not random)")
	}
}

func TestSignAndVerify(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "short message",
			message: []byte("Hello!"),
		},
		{
			name:    "medium message",
			message: []byte("This is a medium length message for testing signatures."),
		},
		{
			name:    "long message",
			message: bytes.Repeat([]byte("Long message content "), 100),
		},
		{
			name:    "empty message",
			message: []byte{},
		},
		{
			name:    "single byte",
			message: []byte{0x42},
		},
		{
			name:    "binary data",
			message: []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign the message
			signature, err := Sign(keyPair.PrivateKey, tt.message)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Check signature size
			if len(signature) != SignatureSize {
				t.Errorf("Signature size = %d, want %d", len(signature), SignatureSize)
			}

			// Verify the signature
			valid, err := Verify(keyPair.PublicKey, tt.message, signature)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			if !valid {
				t.Error("Verify() returned false for valid signature")
			}

			// Test determinism: same message should produce same signature
			signature2, err := Sign(keyPair.PrivateKey, tt.message)
			if err != nil {
				t.Fatalf("Sign() second call error = %v", err)
			}

			if !bytes.Equal(signature, signature2) {
				t.Error("Sign() not deterministic - same inputs produced different signatures")
			}
		})
	}
}

func TestVerifyInvalidSignatures(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	message := []byte("Test message")
	validSignature, err := Sign(keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	tests := []struct {
		name      string
		publicKey []byte
		message   []byte
		signature []byte
		wantValid bool
		wantError bool
	}{
		{
			name:      "valid signature",
			publicKey: keyPair.PublicKey,
			message:   message,
			signature: validSignature,
			wantValid: true,
			wantError: false,
		},
		{
			name:      "wrong message",
			publicKey: keyPair.PublicKey,
			message:   []byte("Wrong message"),
			signature: validSignature,
			wantValid: false,
			wantError: false,
		},
		{
			name:      "tampered signature (first byte)",
			publicKey: keyPair.PublicKey,
			message:   message,
			signature: func() []byte {
				s := make([]byte, len(validSignature))
				copy(s, validSignature)
				s[0] ^= 0xFF
				return s
			}(),
			wantValid: false,
			wantError: false,
		},
		{
			name:      "tampered signature (last byte)",
			publicKey: keyPair.PublicKey,
			message:   message,
			signature: func() []byte {
				s := make([]byte, len(validSignature))
				copy(s, validSignature)
				s[len(s)-1] ^= 0xFF
				return s
			}(),
			wantValid: false,
			wantError: false,
		},
		{
			name: "wrong public key",
			publicKey: func() []byte {
				kp, _ := GenerateKeyPair()
				return kp.PublicKey
			}(),
			message:   message,
			signature: validSignature,
			wantValid: false,
			wantError: false,
		},
		{
			name:      "invalid public key size",
			publicKey: make([]byte, PublicKeySize-1),
			message:   message,
			signature: validSignature,
			wantValid: false,
			wantError: true,
		},
		{
			name:      "invalid signature size",
			publicKey: keyPair.PublicKey,
			message:   message,
			signature: make([]byte, SignatureSize-1),
			wantValid: false,
			wantError: true,
		},
		{
			name:      "nil public key",
			publicKey: nil,
			message:   message,
			signature: validSignature,
			wantValid: false,
			wantError: true,
		},
		{
			name:      "nil signature",
			publicKey: keyPair.PublicKey,
			message:   message,
			signature: nil,
			wantValid: false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := Verify(tt.publicKey, tt.message, tt.signature)

			if tt.wantError {
				if err == nil {
					t.Error("Verify() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Verify() unexpected error = %v", err)
				}
			}

			if valid != tt.wantValid {
				t.Errorf("Verify() = %v, want %v", valid, tt.wantValid)
			}
		})
	}
}

func TestSignErrors(t *testing.T) {
	message := []byte("Test message")

	tests := []struct {
		name       string
		privateKey []byte
		wantError  bool
	}{
		{
			name: "valid private key",
			privateKey: func() []byte {
				kp, _ := GenerateKeyPair()
				return kp.PrivateKey
			}(),
			wantError: false,
		},
		{
			name:       "invalid private key size",
			privateKey: make([]byte, PrivateKeySize-1),
			wantError:  true,
		},
		{
			name:       "nil private key",
			privateKey: nil,
			wantError:  true,
		},
		{
			name:       "empty private key",
			privateKey: []byte{},
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Sign(tt.privateKey, message)

			if tt.wantError {
				if err == nil {
					t.Error("Sign() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Sign() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	// Generate multiple private keys
	key1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}

	if len(key1) != PrivateKeySize {
		t.Errorf("Private key size = %d, want %d", len(key1), PrivateKeySize)
	}

	// Generate another key
	key2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() second call error = %v", err)
	}

	// Verify they're different
	if bytes.Equal(key1, key2) {
		t.Error("Generated identical private keys (not random)")
	}
}

func TestDerivePublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}

	publicKey, err := DerivePublicKey(privateKey)
	if err != nil {
		t.Fatalf("DerivePublicKey() error = %v", err)
	}

	if len(publicKey) != PublicKeySize {
		t.Errorf("Public key size = %d, want %d", len(publicKey), PublicKeySize)
	}

	// Verify deterministic derivation
	publicKey2, err := DerivePublicKey(privateKey)
	if err != nil {
		t.Fatalf("DerivePublicKey() second call error = %v", err)
	}

	if !bytes.Equal(publicKey, publicKey2) {
		t.Error("DerivePublicKey() not deterministic")
	}

	// Test with invalid private key size
	_, err = DerivePublicKey(make([]byte, PrivateKeySize-1))
	if err == nil {
		t.Error("DerivePublicKey() should error with invalid key size")
	}

	// Verify the derived key works for verification
	message := []byte("test message")
	signature, err := Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	valid, err := Verify(publicKey, message, signature)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Derived public key failed to verify signature")
	}
}

func TestGenerateKeyPairFromSeed(t *testing.T) {
	// Create a fixed seed
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Generate key pair from seed
	kp1, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed() error = %v", err)
	}

	// Generate again with same seed
	kp2, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed() second call error = %v", err)
	}

	// Verify deterministic generation
	if !bytes.Equal(kp1.PrivateKey, kp2.PrivateKey) {
		t.Error("GenerateKeyPairFromSeed() not deterministic for private key")
	}
	if !bytes.Equal(kp1.PublicKey, kp2.PublicKey) {
		t.Error("GenerateKeyPairFromSeed() not deterministic for public key")
	}

	// Test with different seed
	seed2 := make([]byte, SeedSize)
	for i := range seed2 {
		seed2[i] = byte(i + 1)
	}

	kp3, err := GenerateKeyPairFromSeed(seed2)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed() error with different seed = %v", err)
	}

	if bytes.Equal(kp1.PrivateKey, kp3.PrivateKey) {
		t.Error("Different seeds produced same private key")
	}
	if bytes.Equal(kp1.PublicKey, kp3.PublicKey) {
		t.Error("Different seeds produced same public key")
	}

	// Test invalid seed size
	_, err = GenerateKeyPairFromSeed(make([]byte, SeedSize-1))
	if err == nil {
		t.Error("GenerateKeyPairFromSeed() should error with invalid seed size")
	}
}

func TestGetSeed(t *testing.T) {
	// Create a seed
	originalSeed := make([]byte, SeedSize)
	for i := range originalSeed {
		originalSeed[i] = byte(i * 2)
	}

	// Generate key pair from seed
	kp, err := GenerateKeyPairFromSeed(originalSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed() error = %v", err)
	}

	// Extract seed from private key
	extractedSeed, err := GetSeed(kp.PrivateKey)
	if err != nil {
		t.Fatalf("GetSeed() error = %v", err)
	}

	// Verify extracted seed matches original
	if !bytes.Equal(originalSeed, extractedSeed) {
		t.Error("Extracted seed doesn't match original seed")
	}

	// Verify we can regenerate the same key pair from extracted seed
	kp2, err := GenerateKeyPairFromSeed(extractedSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed() with extracted seed error = %v", err)
	}

	if !bytes.Equal(kp.PrivateKey, kp2.PrivateKey) {
		t.Error("Key pair regenerated from extracted seed doesn't match")
	}

	// Test with invalid private key size
	_, err = GetSeed(make([]byte, PrivateKeySize-1))
	if err == nil {
		t.Error("GetSeed() should error with invalid private key size")
	}
}

func TestCrossSignatureVerification(t *testing.T) {
	// Test that signatures from different keys don't verify
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	message := []byte("Test message")

	// Sign with key 1
	signature1, err := Sign(kp1.PrivateKey, message)
	if err != nil {
		t.Fatalf("Sign() with key1 error = %v", err)
	}

	// Try to verify with key 2's public key
	valid, err := Verify(kp2.PublicKey, message, signature1)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Signature from key1 incorrectly verified with key2's public key")
	}

	// Sign with key 2
	signature2, err := Sign(kp2.PrivateKey, message)
	if err != nil {
		t.Fatalf("Sign() with key2 error = %v", err)
	}

	// Try to verify with key 1's public key
	valid, err = Verify(kp1.PublicKey, message, signature2)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Signature from key2 incorrectly verified with key1's public key")
	}
}

func TestMultipleMessages(t *testing.T) {
	// Test signing multiple messages with same key
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
	}

	signatures := make([][]byte, len(messages))

	// Sign all messages
	for i, msg := range messages {
		sig, err := Sign(kp.PrivateKey, msg)
		if err != nil {
			t.Fatalf("Sign() message %d error = %v", i, err)
		}
		signatures[i] = sig
	}

	// Verify all signatures are different
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if bytes.Equal(signatures[i], signatures[j]) {
				t.Errorf("Different messages produced same signature (messages %d and %d)", i, j)
			}
		}
	}

	// Verify each signature with correct message
	for i, msg := range messages {
		valid, err := Verify(kp.PublicKey, msg, signatures[i])
		if err != nil {
			t.Fatalf("Verify() message %d error = %v", i, err)
		}
		if !valid {
			t.Errorf("Signature for message %d failed to verify", i)
		}
	}

	// Verify signatures don't work with wrong messages
	for i, sig := range signatures {
		wrongMsgIdx := (i + 1) % len(messages)
		valid, err := Verify(kp.PublicKey, messages[wrongMsgIdx], sig)
		if err != nil {
			t.Fatalf("Verify() cross-check error = %v", err)
		}
		if valid {
			t.Errorf("Signature %d incorrectly verified with message %d", i, wrongMsgIdx)
		}
	}
}
