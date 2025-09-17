package dh

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

	// Verify private key clamping
	if kp1.PrivateKey[0]&7 != 0 {
		t.Error("Private key not properly clamped (first byte)")
	}
	if kp1.PrivateKey[31]&128 != 0 {
		t.Error("Private key not properly clamped (last byte bit 7)")
	}
	if kp1.PrivateKey[31]&64 == 0 {
		t.Error("Private key not properly clamped (last byte bit 6)")
	}
}

func TestDiffieHellmanKeyExchange(t *testing.T) {
	// Alice generates her key pair
	aliceKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Alice GenerateKeyPair() error = %v", err)
	}

	// Bob generates his key pair
	bobKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Bob GenerateKeyPair() error = %v", err)
	}

	// Alice computes shared secret using Bob's public key
	aliceShared, err := ComputeSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Alice ComputeSharedSecret() error = %v", err)
	}

	// Bob computes shared secret using Alice's public key
	bobShared, err := ComputeSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Bob ComputeSharedSecret() error = %v", err)
	}

	// Verify both parties arrived at the same shared secret
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Alice and Bob computed different shared secrets")
	}

	// Verify shared secret has correct size
	if len(aliceShared) != SharedSecretSize {
		t.Errorf("Shared secret size = %d, want %d", len(aliceShared), SharedSecretSize)
	}

	// Verify shared secret is not all zeros
	allZero := true
	for _, b := range aliceShared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Shared secret is all zeros")
	}
}

func TestMultiplePartyKeyExchange(t *testing.T) {
	// Test with 3 parties to ensure uniqueness
	aliceKP, _ := GenerateKeyPair()
	bobKP, _ := GenerateKeyPair()
	charlieKP, _ := GenerateKeyPair()

	// Compute all pairwise shared secrets
	aliceBob, _ := ComputeSharedSecret(aliceKP.PrivateKey, bobKP.PublicKey)
	bobAlice, _ := ComputeSharedSecret(bobKP.PrivateKey, aliceKP.PublicKey)

	aliceCharlie, _ := ComputeSharedSecret(aliceKP.PrivateKey, charlieKP.PublicKey)
	charlieAlice, _ := ComputeSharedSecret(charlieKP.PrivateKey, aliceKP.PublicKey)

	bobCharlie, _ := ComputeSharedSecret(bobKP.PrivateKey, charlieKP.PublicKey)
	charlieBob, _ := ComputeSharedSecret(charlieKP.PrivateKey, bobKP.PublicKey)

	// Verify matching pairs
	if !bytes.Equal(aliceBob, bobAlice) {
		t.Error("Alice-Bob shared secret mismatch")
	}
	if !bytes.Equal(aliceCharlie, charlieAlice) {
		t.Error("Alice-Charlie shared secret mismatch")
	}
	if !bytes.Equal(bobCharlie, charlieBob) {
		t.Error("Bob-Charlie shared secret mismatch")
	}

	// Verify different pairs have different shared secrets
	if bytes.Equal(aliceBob, aliceCharlie) {
		t.Error("Alice has same shared secret with Bob and Charlie")
	}
	if bytes.Equal(aliceBob, bobCharlie) {
		t.Error("Alice-Bob and Bob-Charlie have same shared secret")
	}
}

func TestComputeSharedSecretErrors(t *testing.T) {
	validPrivateKey, _ := GeneratePrivateKey()
	validPublicKey, _ := DerivePublicKey(validPrivateKey)

	tests := []struct {
		name          string
		privateKey    []byte
		publicKey     []byte
		wantError     bool
		errorContains string
	}{
		{
			name:          "invalid private key size",
			privateKey:    make([]byte, 31),
			publicKey:     validPublicKey,
			wantError:     true,
			errorContains: "private key must be 32 bytes",
		},
		{
			name:          "invalid public key size",
			privateKey:    validPrivateKey,
			publicKey:     make([]byte, 31),
			wantError:     true,
			errorContains: "public key must be 32 bytes",
		},
		{
			name:          "nil private key",
			privateKey:    nil,
			publicKey:     validPublicKey,
			wantError:     true,
			errorContains: "private key must be 32 bytes",
		},
		{
			name:          "nil public key",
			privateKey:    validPrivateKey,
			publicKey:     nil,
			wantError:     true,
			errorContains: "public key must be 32 bytes",
		},
		{
			name:       "valid keys",
			privateKey: validPrivateKey,
			publicKey:  validPublicKey,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ComputeSharedSecret(tt.privateKey, tt.publicKey)
			if tt.wantError {
				if err == nil {
					t.Error("ComputeSharedSecret() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ComputeSharedSecret() unexpected error = %v", err)
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

	// Verify clamping
	if key1[0]&7 != 0 {
		t.Error("Private key not properly clamped (first byte)")
	}
	if key1[31]&128 != 0 {
		t.Error("Private key not properly clamped (last byte bit 7)")
	}
	if key1[31]&64 == 0 {
		t.Error("Private key not properly clamped (last byte bit 6)")
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
	_, err = DerivePublicKey(make([]byte, 31))
	if err == nil {
		t.Error("DerivePublicKey() should error with invalid key size")
	}
}

func TestConsistentKeyDerivation(t *testing.T) {
	// Verify that GenerateKeyPair and separate generation produce same results
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}

	publicKey, err := DerivePublicKey(privateKey)
	if err != nil {
		t.Fatalf("DerivePublicKey() error = %v", err)
	}

	// Now use these keys for DH
	otherKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	shared1, err := ComputeSharedSecret(privateKey, otherKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret() error = %v", err)
	}

	shared2, err := ComputeSharedSecret(otherKeyPair.PrivateKey, publicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret() error = %v", err)
	}

	if !bytes.Equal(shared1, shared2) {
		t.Error("Shared secrets don't match when using separately generated keys")
	}
}
