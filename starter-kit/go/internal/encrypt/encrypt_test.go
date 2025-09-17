package encrypt

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		wantError bool
	}{
		{
			name:      "AES-128 (16 bytes)",
			keySize:   16,
			wantError: false,
		},
		{
			name:      "AES-192 (24 bytes)",
			keySize:   24,
			wantError: false,
		},
		{
			name:      "AES-256 (32 bytes)",
			keySize:   32,
			wantError: false,
		},
		{
			name:      "invalid size (15 bytes)",
			keySize:   15,
			wantError: true,
		},
		{
			name:      "invalid size (20 bytes)",
			keySize:   20,
			wantError: true,
		},
		{
			name:      "invalid size (0 bytes)",
			keySize:   0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keySize)

			if tt.wantError {
				if err == nil {
					t.Errorf("GenerateKey() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateKey() unexpected error = %v", err)
			}

			if len(key) != tt.keySize {
				t.Errorf("GenerateKey() returned %d bytes, want %d", len(key), tt.keySize)
			}

			// Check that keys are random (different calls produce different keys)
			key2, err := GenerateKey(tt.keySize)
			if err != nil {
				t.Fatalf("GenerateKey() second call error = %v", err)
			}

			if bytes.Equal(key, key2) {
				t.Error("GenerateKey() produced identical keys (not random)")
			}
		})
	}
}

func TestGenerateNonce(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{
			name: "12 bytes (GCM nonce)",
			size: 12,
		},
		{
			name: "16 bytes (CTR IV)",
			size: 16,
		},
		{
			name: "8 bytes",
			size: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce, err := GenerateNonce(tt.size)
			if err != nil {
				t.Fatalf("GenerateNonce() error = %v", err)
			}

			if len(nonce) != tt.size {
				t.Errorf("GenerateNonce() returned %d bytes, want %d", len(nonce), tt.size)
			}

			// Check that nonces are random
			nonce2, err := GenerateNonce(tt.size)
			if err != nil {
				t.Fatalf("GenerateNonce() second call error = %v", err)
			}

			if bytes.Equal(nonce, nonce2) {
				t.Error("GenerateNonce() produced identical nonces (not random)")
			}
		})
	}
}

func TestEncryptDecryptAESCTR(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		plaintext []byte
	}{
		{
			name:      "AES-128 with short message",
			keySize:   16,
			plaintext: []byte("Hello!"),
		},
		{
			name:      "AES-192 with medium message",
			keySize:   24,
			plaintext: []byte("This is a medium length message for testing."),
		},
		{
			name:      "AES-256 with long message",
			keySize:   32,
			plaintext: bytes.Repeat([]byte("Long message "), 100),
		},
		{
			name:      "AES-256 with empty message",
			keySize:   32,
			plaintext: []byte{},
		},
		{
			name:      "AES-256 with single byte",
			keySize:   32,
			plaintext: []byte{0x42},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keySize)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			iv, err := GenerateNonce(16)
			if err != nil {
				t.Fatalf("GenerateNonce() error = %v", err)
			}

			// Encrypt
			ciphertext, err := EncryptAESCTR(key, iv, tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptAESCTR() error = %v", err)
			}

			// Verify ciphertext length matches plaintext
			if len(ciphertext) != len(tt.plaintext) {
				t.Errorf("Ciphertext length %d != plaintext length %d", len(ciphertext), len(tt.plaintext))
			}

			// Verify ciphertext is different from plaintext (unless empty)
			if len(tt.plaintext) > 0 && bytes.Equal(ciphertext, tt.plaintext) {
				t.Error("Ciphertext equals plaintext (no encryption occurred)")
			}

			// Decrypt
			decrypted, err := DecryptAESCTR(key, iv, ciphertext)
			if err != nil {
				t.Fatalf("DecryptAESCTR() error = %v", err)
			}

			// Verify decryption recovers original plaintext
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Error("Decrypted text does not match original plaintext")
			}
		})
	}
}

func TestAESCTRInvalidInputs(t *testing.T) {
	validKey := make([]byte, 32)
	validIV := make([]byte, 16)
	validPlaintext := []byte("test")

	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		wantError bool
	}{
		{
			name:      "invalid key size (15 bytes)",
			key:       make([]byte, 15),
			iv:        validIV,
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "invalid IV size (15 bytes)",
			key:       validKey,
			iv:        make([]byte, 15),
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "invalid IV size (17 bytes)",
			key:       validKey,
			iv:        make([]byte, 17),
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "nil key",
			key:       nil,
			iv:        validIV,
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "nil IV",
			key:       validKey,
			iv:        nil,
			plaintext: validPlaintext,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptAESCTR(tt.key, tt.iv, tt.plaintext)
			if tt.wantError && err == nil {
				t.Error("EncryptAESCTR() expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("EncryptAESCTR() unexpected error = %v", err)
			}
		})
	}
}

func TestEncryptDecryptAESGCM(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		plaintext []byte
	}{
		{
			name:      "AES-128-GCM with short message",
			keySize:   16,
			plaintext: []byte("Hello!"),
		},
		{
			name:      "AES-192-GCM with medium message",
			keySize:   24,
			plaintext: []byte("This is a medium length message for testing."),
		},
		{
			name:      "AES-256-GCM with long message",
			keySize:   32,
			plaintext: bytes.Repeat([]byte("Long message "), 100),
		},
		{
			name:      "AES-256-GCM with empty message",
			keySize:   32,
			plaintext: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keySize)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			nonce, err := GenerateNonce(12)
			if err != nil {
				t.Fatalf("GenerateNonce() error = %v", err)
			}

			// Encrypt
			ciphertext, err := EncryptAESGCM(key, nonce, tt.plaintext, nil)
			if err != nil {
				t.Fatalf("EncryptAESGCM() error = %v", err)
			}

			// Verify ciphertext includes auth tag (16 bytes longer than plaintext)
			if len(ciphertext) != len(tt.plaintext)+16 {
				t.Errorf("Ciphertext length %d != plaintext length + 16 (%d)",
					len(ciphertext), len(tt.plaintext)+16)
			}

			// Decrypt
			decrypted, err := DecryptAESGCM(key, nonce, ciphertext, nil)
			if err != nil {
				t.Fatalf("DecryptAESGCM() error = %v", err)
			}

			// Verify decryption recovers original plaintext
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Error("Decrypted text does not match original plaintext")
			}
		})
	}
}

func TestAESGCMAuthentication(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	nonce, err := GenerateNonce(12)
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}

	plaintext := []byte("Secret message")

	// Encrypt
	ciphertext, err := EncryptAESGCM(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptAESGCM() error = %v", err)
	}

	// Test authentication failures
	tests := []struct {
		name             string
		modifyCiphertext func([]byte) []byte
	}{
		{
			name: "tampered ciphertext (first byte)",
			modifyCiphertext: func(ct []byte) []byte {
				modified := make([]byte, len(ct))
				copy(modified, ct)
				modified[0] ^= 0xFF
				return modified
			},
		},
		{
			name: "tampered auth tag (last byte)",
			modifyCiphertext: func(ct []byte) []byte {
				modified := make([]byte, len(ct))
				copy(modified, ct)
				modified[len(modified)-1] ^= 0xFF
				return modified
			},
		},
		{
			name: "truncated ciphertext",
			modifyCiphertext: func(ct []byte) []byte {
				return ct[:len(ct)-1]
			},
		},
		{
			name: "extended ciphertext",
			modifyCiphertext: func(ct []byte) []byte {
				return append(ct, 0x00)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tamperedCiphertext := tt.modifyCiphertext(ciphertext)
			_, err := DecryptAESGCM(key, nonce, tamperedCiphertext, nil)
			if err == nil {
				t.Error("DecryptAESGCM() should fail with tampered ciphertext")
			}
		})
	}

	// Test wrong key
	t.Run("wrong key", func(t *testing.T) {
		wrongKey, _ := GenerateKey(32)
		_, err := DecryptAESGCM(wrongKey, nonce, ciphertext, nil)
		if err == nil {
			t.Error("DecryptAESGCM() should fail with wrong key")
		}
	})

	// Test wrong nonce
	t.Run("wrong nonce", func(t *testing.T) {
		wrongNonce, _ := GenerateNonce(12)
		_, err := DecryptAESGCM(key, wrongNonce, ciphertext, nil)
		if err == nil {
			t.Error("DecryptAESGCM() should fail with wrong nonce")
		}
	})
}

func TestAESGCMInvalidInputs(t *testing.T) {
	validKey := make([]byte, 32)
	validNonce := make([]byte, 12)
	validPlaintext := []byte("test")

	tests := []struct {
		name      string
		key       []byte
		nonce     []byte
		plaintext []byte
		wantError bool
	}{
		{
			name:      "invalid key size (15 bytes)",
			key:       make([]byte, 15),
			nonce:     validNonce,
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "invalid nonce size (11 bytes)",
			key:       validKey,
			nonce:     make([]byte, 11),
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "invalid nonce size (13 bytes)",
			key:       validKey,
			nonce:     make([]byte, 13),
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "nil key",
			key:       nil,
			nonce:     validNonce,
			plaintext: validPlaintext,
			wantError: true,
		},
		{
			name:      "nil nonce",
			key:       validKey,
			nonce:     nil,
			plaintext: validPlaintext,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptAESGCM(tt.key, tt.nonce, tt.plaintext, nil)
			if tt.wantError && err == nil {
				t.Error("EncryptAESGCM() expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("EncryptAESGCM() unexpected error = %v", err)
			}
		})
	}
}

func TestEncryptDecryptAESGCMWithAAD(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	nonce, err := GenerateNonce(12)
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{
			name:      "with AAD",
			plaintext: []byte("Secret message"),
			aad:       []byte("header:value,timestamp:12345"),
		},
		{
			name:      "empty AAD",
			plaintext: []byte("Secret message"),
			aad:       []byte{},
		},
		{
			name:      "empty plaintext with AAD",
			plaintext: []byte{},
			aad:       []byte("metadata"),
		},
		{
			name:      "large AAD",
			plaintext: []byte("Secret"),
			aad:       bytes.Repeat([]byte("metadata"), 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt with AAD
			ciphertext, err := EncryptAESGCM(key, nonce, tt.plaintext, tt.aad)
			if err != nil {
				t.Fatalf("EncryptAESGCM() error = %v", err)
			}

			// Decrypt with same AAD
			decrypted, err := DecryptAESGCM(key, nonce, ciphertext, tt.aad)
			if err != nil {
				t.Fatalf("DecryptAESGCM() error = %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Error("Decrypted text does not match original plaintext")
			}

			// Try to decrypt with wrong AAD
			wrongAAD := append(tt.aad, []byte("extra")...)
			_, err = DecryptAESGCM(key, nonce, ciphertext, wrongAAD)
			if err == nil {
				t.Error("DecryptAESGCM() should fail with wrong AAD")
			}
		})
	}
}

func TestAADAuthentication(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	nonce, err := GenerateNonce(12)
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}

	plaintext := []byte("Secret message")
	aad := []byte("user:alice,action:read")

	// Encrypt with AAD
	ciphertext, err := EncryptAESGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptAESGCM() error = %v", err)
	}

	tests := []struct {
		name      string
		aad       []byte
		wantError bool
	}{
		{
			name:      "correct AAD",
			aad:       aad,
			wantError: false,
		},
		{
			name:      "modified AAD",
			aad:       []byte("user:bob,action:read"),
			wantError: true,
		},
		{
			name:      "truncated AAD",
			aad:       aad[:len(aad)-5],
			wantError: true,
		},
		{
			name:      "extended AAD",
			aad:       append(aad, []byte(",extra:data")...),
			wantError: true,
		},
		{
			name:      "empty AAD when encrypted with AAD",
			aad:       []byte{},
			wantError: true,
		},
		{
			name:      "nil AAD when encrypted with AAD",
			aad:       nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptAESGCM(key, nonce, ciphertext, tt.aad)
			if tt.wantError && err == nil {
				t.Error("DecryptAESGCM() expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("DecryptAESGCM() unexpected error = %v", err)
			}
		})
	}
}
