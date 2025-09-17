package sign_test

import (
	"encoding/hex"
	"fmt"

	"appliedcryptography-starter-kit/internal/sign"
)

func ExampleGenerateKeyPair() {
	// Generate a key pair for Ed25519 digital signatures
	keyPair, err := sign.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Private key size: %d bytes\n", len(keyPair.PrivateKey))
	fmt.Printf("Public key size: %d bytes\n", len(keyPair.PublicKey))
	fmt.Printf("Keys generated successfully: %v\n", keyPair.PrivateKey != nil && keyPair.PublicKey != nil)
	// Output:
	// Private key size: 64 bytes
	// Public key size: 32 bytes
	// Keys generated successfully: true
}

func ExampleSign() {
	// Generate a key pair
	keyPair, err := sign.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Message to sign
	message := []byte("This is an important message")

	// Sign the message
	signature, err := sign.Sign(keyPair.PrivateKey, message)
	if err != nil {
		fmt.Printf("Signing error: %v\n", err)
		return
	}

	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Signature size: %d bytes\n", len(signature))
	fmt.Printf("Signature created: %v\n", signature != nil)
	// Output:
	// Message: This is an important message
	// Signature size: 64 bytes
	// Signature created: true
}

func ExampleVerify() {
	// Generate a key pair
	keyPair, err := sign.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Message to sign
	message := []byte("Verify this message")

	// Sign the message
	signature, err := sign.Sign(keyPair.PrivateKey, message)
	if err != nil {
		fmt.Printf("Signing error: %v\n", err)
		return
	}

	// Verify the signature
	valid, err := sign.Verify(keyPair.PublicKey, message, signature)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
		return
	}
	fmt.Printf("Signature is valid: %v\n", valid)

	// Try to verify with wrong message
	wrongMessage := []byte("Different message")
	valid, err = sign.Verify(keyPair.PublicKey, wrongMessage, signature)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
		return
	}
	fmt.Printf("Signature valid for wrong message: %v\n", valid)

	// Output:
	// Signature is valid: true
	// Signature valid for wrong message: false
}

func ExampleGenerateKeyPairFromSeed() {
	// Use a fixed seed for deterministic key generation
	// In practice, use a secure random seed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Generate key pair from seed
	keyPair1, err := sign.GenerateKeyPairFromSeed(seed)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Generate again with same seed
	keyPair2, err := sign.GenerateKeyPairFromSeed(seed)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// The keys should be identical
	fmt.Printf("Private keys match: %v\n", string(keyPair1.PrivateKey) == string(keyPair2.PrivateKey))
	fmt.Printf("Public keys match: %v\n", string(keyPair1.PublicKey) == string(keyPair2.PublicKey))
	// Output:
	// Private keys match: true
	// Public keys match: true
}

func ExampleDerivePublicKey() {
	// First generate a private key
	privateKey, err := sign.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Private key error: %v\n", err)
		return
	}

	// Derive the public key from the private key
	publicKey, err := sign.DerivePublicKey(privateKey)
	if err != nil {
		fmt.Printf("Public key derivation error: %v\n", err)
		return
	}

	fmt.Printf("Private key size: %d bytes\n", len(privateKey))
	fmt.Printf("Public key size: %d bytes\n", len(publicKey))
	fmt.Printf("Public key derived: %v\n", publicKey != nil)
	// Output:
	// Private key size: 64 bytes
	// Public key size: 32 bytes
	// Public key derived: true
}

// Example_digitalSignatureWorkflow demonstrates a complete digital signature workflow
func Example_digitalSignatureWorkflow() {
	fmt.Println("=== Digital Signature Demo ===")
	fmt.Println()

	// Step 1: Alice generates her signing key pair
	fmt.Println("1. Alice generates her signing key pair")
	aliceKeyPair, err := sign.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   Alice's public key: %s...\n", hex.EncodeToString(aliceKeyPair.PublicKey)[:16])
	fmt.Println()

	// Step 2: Alice creates and signs a message
	fmt.Println("2. Alice creates and signs a message")
	message := []byte("I, Alice, approve this transaction.")
	signature, err := sign.Sign(aliceKeyPair.PrivateKey, message)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   Message: %s\n", message)
	fmt.Printf("   Signature: %s...\n", hex.EncodeToString(signature)[:16])
	fmt.Println()

	// Step 3: Alice sends message, signature, and public key to Bob
	fmt.Println("3. Alice sends the message, signature, and her public key to Bob")
	fmt.Println("   (The public key can be shared beforehand or through a PKI)")
	fmt.Println()

	// Step 4: Bob verifies the signature
	fmt.Println("4. Bob verifies Alice's signature")
	valid, err := sign.Verify(aliceKeyPair.PublicKey, message, signature)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if valid {
		fmt.Println("   ✓ Signature is valid! Bob knows:")
		fmt.Println("     - The message came from Alice (authentication)")
		fmt.Println("     - The message wasn't modified (integrity)")
		fmt.Println("     - Alice can't deny signing it (non-repudiation)")
	} else {
		fmt.Println("   ✗ Signature is invalid!")
	}
	fmt.Println()

	// Step 5: Demonstrate what happens if message is tampered
	fmt.Println("5. What if someone tampers with the message?")
	tamperedMessage := []byte("I, Alice, approve this fraudulent transaction.")
	tamperedValid, err := sign.Verify(aliceKeyPair.PublicKey, tamperedMessage, signature)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if !tamperedValid {
		fmt.Println("   ✓ Tampered message detected! Signature doesn't match.")
	} else {
		fmt.Println("   ✗ Something went wrong - tampered message verified!")
	}
}

// Example_multipleSigners shows multiple parties signing different messages
func Example_multipleSigners() {
	// Two parties generate their signing keys
	aliceKP, _ := sign.GenerateKeyPair()
	bobKP, _ := sign.GenerateKeyPair()

	// Each signs their own message
	aliceMsg := []byte("Alice's statement")
	bobMsg := []byte("Bob's statement")

	aliceSig, _ := sign.Sign(aliceKP.PrivateKey, aliceMsg)
	bobSig, _ := sign.Sign(bobKP.PrivateKey, bobMsg)

	// Verify Alice's signature with Alice's public key
	aliceValid, _ := sign.Verify(aliceKP.PublicKey, aliceMsg, aliceSig)

	// Try to verify Alice's signature with Bob's public key (should fail)
	aliceWithBobKey, _ := sign.Verify(bobKP.PublicKey, aliceMsg, aliceSig)

	// Verify Bob's signature with Bob's public key
	bobValid, _ := sign.Verify(bobKP.PublicKey, bobMsg, bobSig)

	fmt.Println("Multiple signers:")
	fmt.Printf("Alice's signature verified with Alice's key: %v\n", aliceValid)
	fmt.Printf("Alice's signature verified with Bob's key: %v\n", aliceWithBobKey)
	fmt.Printf("Bob's signature verified with Bob's key: %v\n", bobValid)
	// Output:
	// Multiple signers:
	// Alice's signature verified with Alice's key: true
	// Alice's signature verified with Bob's key: false
	// Bob's signature verified with Bob's key: true
}

// Example_documentSigning shows a practical document signing scenario
func Example_documentSigning() {
	// Generate signing key for document author
	authorKeyPair, err := sign.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Document content
	document := []byte("Contract: Party A agrees to deliver 100 widgets to Party B by December 31, 2024.")

	// Sign the document
	documentSignature, err := sign.Sign(authorKeyPair.PrivateKey, document)
	if err != nil {
		fmt.Printf("Error signing: %v\n", err)
		return
	}

	// Later, anyone with the public key can verify
	verified, err := sign.Verify(authorKeyPair.PublicKey, document, documentSignature)
	if err != nil {
		fmt.Printf("Error verifying: %v\n", err)
		return
	}

	fmt.Printf("Document: %.30s...\n", document)
	fmt.Printf("Signature length: %d bytes\n", len(documentSignature))
	fmt.Printf("Document verified: %v\n", verified)
	// Output:
	// Document: Contract: Party A agrees to de...
	// Signature length: 64 bytes
	// Document verified: true
}
