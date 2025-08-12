//! # Digital Signatures
//!
//! This module implements digital signature algorithms as covered in Topic 1.8
//! of the Applied Cryptography course, focusing on elliptic curve signatures.
//!
//! ## Signature Schemes
//!
//! - **EdDSA (Ed25519)**: Edwards-curve Digital Signature Algorithm
//! - **ECDSA**: Elliptic Curve Digital Signature Algorithm
//!
//! ## Security Properties
//!
//! - **Unforgeability**: Can't create valid signatures without the private key
//! - **Non-repudiation**: Signer can't deny creating the signature
//! - **Public verifiability**: Anyone can verify with the public key

use crate::error::{CryptoError, Result};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::{Signer, Verifier},
};

/// Ed25519 signature scheme (EdDSA)
///
/// Ed25519 is a modern signature scheme with several advantages:
/// - Deterministic (no random nonce needed)
/// - Fast signing and verification
/// - Small signatures (64 bytes)
/// - Strong security (128-bit security level)
pub struct Ed25519 {
    key_pair: KeyPair,
}

impl Ed25519 {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        let key_pair = KeyPair::generate();

        Self { key_pair }
    }

    /// Create from an existing signing key
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Result<Self> {
        let seed = Seed::from_slice(key_bytes).map_err(|e| CryptoError::InvalidSecretKey {
            reason: e.to_string(),
        })?;
        let key_pair = KeyPair::from_seed(seed);

        Ok(Self { key_pair })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.key_pair.pk
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.key_pair.sk.sign(message, None);
        *signature
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let sig = Signature::from_slice(signature).map_err(|e| CryptoError::InvalidSignature {
            reason: e.to_string(),
        })?;
        self.key_pair
            .pk
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Verify a signature using only the public key
    pub fn verify_with_public_key(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        let pk = PublicKey::from_slice(public_key).map_err(|e| CryptoError::InvalidPublicKey {
            reason: e.to_string(),
        })?;

        let sig = Signature::from_slice(signature).map_err(|e| CryptoError::InvalidSignature {
            reason: e.to_string(),
        })?;
        pk.verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// ECDSA signature scheme using P-256 curve
///
/// ECDSA is widely deployed but has some disadvantages:
/// - Requires a random nonce (critical for security)
/// - Malleable signatures (can be modified without private key)
/// - More complex than EdDSA
pub struct EcdsaP256 {
    signing_key: P256SigningKey,
    verifying_key: P256VerifyingKey,
}

impl EcdsaP256 {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate() -> Self {
        let signing_key = P256SigningKey::random(&mut p256::ecdsa::signature::rand_core::OsRng);
        let verifying_key = *signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign a message
    ///
    /// # Security Warning
    /// ECDSA requires a unique random nonce for each signature.
    /// Nonce reuse or bias can leak the private key!
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: P256Signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig =
            P256Signature::from_slice(signature).map_err(|e| CryptoError::InvalidSignature {
                reason: e.to_string(),
            })?;

        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Get the public key bytes (compressed format)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }
}

/// Batch signature verification for Ed25519
///
/// Verifying multiple signatures together can be more efficient
pub struct BatchVerifier {
    entries: Vec<(PublicKey, Vec<u8>, Signature)>,
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a signature to verify
    pub fn add(
        &mut self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        let pk = PublicKey::from_slice(public_key).map_err(|e| CryptoError::InvalidPublicKey {
            reason: e.to_string(),
        })?;

        let sig = Signature::from_slice(signature).map_err(|e| CryptoError::InvalidSignature {
            reason: e.to_string(),
        })?;

        self.entries.push((pk, message.to_vec(), sig));
        Ok(())
    }

    /// Verify all signatures in the batch
    pub fn verify_all(&self) -> bool {
        // In practice, batch verification can be optimized
        // For now, we verify individually
        for (key, msg, sig) in &self.entries {
            if key.verify(msg, sig).is_err() {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519::generate();
        let message = b"Hello, Ed25519!";

        let signature = signer.sign(message);
        assert!(signer.verify(message, &signature).is_ok());

        // Verify with wrong message should fail
        assert!(signer.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_ed25519_public_key_verification() {
        let signer = Ed25519::generate();
        let message = b"Test message";

        let signature = signer.sign(message);
        let public_key = signer.public_key_bytes();

        // Verify using only public key
        assert!(Ed25519::verify_with_public_key(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_ecdsa_p256_sign_verify() {
        let signer = EcdsaP256::generate();
        let message = b"Hello, ECDSA!";

        let signature = signer.sign(message);
        assert!(signer.verify(message, &signature).is_ok());

        // Verify with wrong message should fail
        assert!(signer.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_batch_verification() {
        let mut batch = BatchVerifier::new();

        // Create multiple signatures
        for i in 0..5 {
            let signer = Ed25519::generate();
            let message = format!("Message {}", i);
            let signature = signer.sign(message.as_bytes());

            batch
                .add(&signer.public_key_bytes(), message.as_bytes(), &signature)
                .unwrap();
        }

        assert!(batch.verify_all());
    }

    #[test]
    fn test_signature_deterministic() {
        // Ed25519 is deterministic - same message produces same signature
        let key_bytes = [42u8; 32];
        let signer = Ed25519::from_bytes(&key_bytes).unwrap();
        let message = b"Deterministic test";

        let sig1 = signer.sign(message);
        let sig2 = signer.sign(message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signature_uniqueness() {
        // Different messages produce different signatures
        let signer = Ed25519::generate();

        let sig1 = signer.sign(b"Message 1");
        let sig2 = signer.sign(b"Message 2");

        assert_ne!(sig1, sig2);
    }
}
