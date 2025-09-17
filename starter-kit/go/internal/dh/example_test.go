package dh_test

import (
	"encoding/hex"
	"fmt"

	"appliedcryptography-starter-kit/internal/dh"
)

func ExampleGenerateKeyPair() {
	// Generate a key pair for Diffie-Hellman key exchange
	keyPair, err := dh.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Private key size: %d bytes\n", len(keyPair.PrivateKey))
	fmt.Printf("Public key size: %d bytes\n", len(keyPair.PublicKey))
	fmt.Printf("Keys generated successfully: %v\n", keyPair.PrivateKey != nil && keyPair.PublicKey != nil)
	// Output:
	// Private key size: 32 bytes
	// Public key size: 32 bytes
	// Keys generated successfully: true
}

func ExampleComputeSharedSecret() {
	// Alice generates her key pair
	aliceKeyPair, err := dh.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Alice key generation error: %v\n", err)
		return
	}

	// Bob generates his key pair
	bobKeyPair, err := dh.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Bob key generation error: %v\n", err)
		return
	}

	// Alice computes the shared secret using Bob's public key
	aliceSharedSecret, err := dh.ComputeSharedSecret(
		aliceKeyPair.PrivateKey,
		bobKeyPair.PublicKey,
	)
	if err != nil {
		fmt.Printf("Alice shared secret error: %v\n", err)
		return
	}

	// Bob computes the shared secret using Alice's public key
	bobSharedSecret, err := dh.ComputeSharedSecret(
		bobKeyPair.PrivateKey,
		aliceKeyPair.PublicKey,
	)
	if err != nil {
		fmt.Printf("Bob shared secret error: %v\n", err)
		return
	}

	// Both parties should have the same shared secret
	fmt.Printf("Shared secret size: %d bytes\n", len(aliceSharedSecret))
	fmt.Printf("Secrets match: %v\n", string(aliceSharedSecret) == string(bobSharedSecret))
	// Output:
	// Shared secret size: 32 bytes
	// Secrets match: true
}

func ExampleGeneratePrivateKey() {
	// Generate a private key for X25519
	privateKey, err := dh.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Private key size: %d bytes\n", len(privateKey))
	fmt.Printf("Key generated: %v\n", privateKey != nil)
	// Output:
	// Private key size: 32 bytes
	// Key generated: true
}

func ExampleDerivePublicKey() {
	// First generate a private key
	privateKey, err := dh.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Private key error: %v\n", err)
		return
	}

	// Derive the public key from the private key
	publicKey, err := dh.DerivePublicKey(privateKey)
	if err != nil {
		fmt.Printf("Public key derivation error: %v\n", err)
		return
	}

	fmt.Printf("Public key size: %d bytes\n", len(publicKey))
	fmt.Printf("Public key derived: %v\n", publicKey != nil)
	// Output:
	// Public key size: 32 bytes
	// Public key derived: true
}

// Example_diffieHellmanWorkflow demonstrates a complete Diffie-Hellman key exchange
func Example_diffieHellmanWorkflow() {
	fmt.Println("=== Diffie-Hellman Key Exchange Demo ===")
	fmt.Println()

	// Step 1: Alice generates her key pair
	fmt.Println("1. Alice generates her key pair")
	aliceKeyPair, err := dh.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   Alice's public key: %s...\n", hex.EncodeToString(aliceKeyPair.PublicKey)[:16])
	fmt.Println()

	// Step 2: Bob generates his key pair
	fmt.Println("2. Bob generates his key pair")
	bobKeyPair, err := dh.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   Bob's public key: %s...\n", hex.EncodeToString(bobKeyPair.PublicKey)[:16])
	fmt.Println()

	// Step 3: They exchange public keys (over an insecure channel)
	fmt.Println("3. Alice and Bob exchange public keys")
	fmt.Println("   (This can happen over an insecure channel)")
	fmt.Println()

	// Step 4: Alice computes the shared secret
	fmt.Println("4. Alice computes shared secret using Bob's public key")
	aliceSharedSecret, err := dh.ComputeSharedSecret(
		aliceKeyPair.PrivateKey,
		bobKeyPair.PublicKey,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   Alice's shared secret: %s...\n", hex.EncodeToString(aliceSharedSecret)[:16])
	fmt.Println()

	// Step 5: Bob computes the shared secret
	fmt.Println("5. Bob computes shared secret using Alice's public key")
	bobSharedSecret, err := dh.ComputeSharedSecret(
		bobKeyPair.PrivateKey,
		aliceKeyPair.PublicKey,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   Bob's shared secret: %s...\n", hex.EncodeToString(bobSharedSecret)[:16])
	fmt.Println()

	// Step 6: Verify they have the same secret
	fmt.Println("6. Verification")
	if string(aliceSharedSecret) == string(bobSharedSecret) {
		fmt.Println("   ✓ Alice and Bob have the same shared secret!")
		fmt.Println("   They can now use this secret for symmetric encryption")
	} else {
		fmt.Println("   ✗ Something went wrong - secrets don't match")
	}
}

// Example_multiPartyScenario shows that each pair gets a unique shared secret
func Example_multiPartyScenario() {
	// Three parties generate their key pairs
	aliceKP, _ := dh.GenerateKeyPair()
	bobKP, _ := dh.GenerateKeyPair()
	charlieKP, _ := dh.GenerateKeyPair()

	// Alice computes shared secrets with Bob and Charlie
	aliceBobSecret, _ := dh.ComputeSharedSecret(aliceKP.PrivateKey, bobKP.PublicKey)
	aliceCharlieSecret, _ := dh.ComputeSharedSecret(aliceKP.PrivateKey, charlieKP.PublicKey)

	// Bob computes shared secret with Alice
	bobAliceSecret, _ := dh.ComputeSharedSecret(bobKP.PrivateKey, aliceKP.PublicKey)

	fmt.Println("Multi-party key exchange:")
	fmt.Printf("Alice-Bob secret matches: %v\n",
		string(aliceBobSecret) == string(bobAliceSecret))
	fmt.Printf("Alice-Bob and Alice-Charlie secrets are different: %v\n",
		string(aliceBobSecret) != string(aliceCharlieSecret))
	// Output:
	// Multi-party key exchange:
	// Alice-Bob secret matches: true
	// Alice-Bob and Alice-Charlie secrets are different: true
}
