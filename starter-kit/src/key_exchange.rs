//! # Diffie-Hellman Key Exchange
//!
//! This module implements the Diffie-Hellman key exchange protocol as covered
//! in Topic 1.7 of the Applied Cryptography course.
//!
//! ## Key Concepts
//!
//! - **Discrete Logarithm Problem**: The hardness assumption underlying DH
//! - **Computational Diffie-Hellman (CDH)**: Computing g^(ab) from g^a and g^b
//! - **Decisional Diffie-Hellman (DDH)**: Distinguishing g^(ab) from random
//!
//! ## Implementations
//!
//! - Classic DH in prime fields (educational)
//! - Elliptic Curve DH using X25519 (production-ready)
//! - Authenticated DH variants

use crate::error::{CryptoError, Result};
use ed25519_compact::{
    KeyPair as Ed25519KeyPair, Noise, PublicKey as Ed25519PublicKey, Seed, Signature, x25519,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;

/// Classic Diffie-Hellman implementation in prime fields
///
/// This is for educational purposes to understand the mathematical foundation
pub struct ClassicDiffieHellman {
    /// Prime modulus p (should be a safe prime: p = 2q + 1 where q is prime)
    p: BigUint,
    /// Generator g (should generate a large subgroup)
    g: BigUint,
}

impl ClassicDiffieHellman {
    /// Create a new DH instance with RFC 3526 2048-bit MODP group
    pub fn new_rfc3526_2048() -> Self {
        // RFC 3526 2048-bit MODP Group (Group 14)
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
                     020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
                     4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
                     EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
                     98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
                     9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
                     E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
                     3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

        let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap();
        let g = BigUint::from(2u32);

        Self { p, g }
    }

    /// Create a new DH instance with custom parameters
    ///
    /// # Security Warning
    /// Using custom parameters requires careful validation. Prefer standard groups.
    pub fn new(p: BigUint, g: BigUint) -> Result<Self> {
        // Basic parameter validation
        if p.bits() < 2048 {
            return Err(CryptoError::InvalidInput {
                reason: "Prime must be at least 2048 bits".to_string(),
            });
        }

        if g <= BigUint::one() || g >= p {
            return Err(CryptoError::InvalidInput {
                reason: "Generator must be in range (1, p)".to_string(),
            });
        }

        Ok(Self { p, g })
    }

    /// Generate a private key (random exponent)
    pub fn generate_private_key(&self) -> BigUint {
        // Generate random number in range [2, p-2]
        let min = BigUint::from(2u32);
        let max = &self.p - 2u32;
        let mut rng = rand::thread_rng();
        rng.gen_biguint_range(&min, &max)
    }

    /// Compute public key from private key: g^private mod p
    pub fn compute_public_key(&self, private_key: &BigUint) -> BigUint {
        self.g.modpow(private_key, &self.p)
    }

    /// Compute shared secret: other_public^private mod p
    pub fn compute_shared_secret(
        &self,
        private_key: &BigUint,
        other_public_key: &BigUint,
    ) -> Result<BigUint> {
        // Validate other's public key
        if other_public_key <= &BigUint::one() || other_public_key >= &self.p {
            return Err(CryptoError::InvalidPublicKey {
                reason: "Public key out of valid range".to_string(),
            });
        }

        // Check for small subgroup attacks
        if self.is_weak_public_key(other_public_key) {
            return Err(CryptoError::InvalidPublicKey {
                reason: "Weak public key detected (small subgroup)".to_string(),
            });
        }

        Ok(other_public_key.modpow(private_key, &self.p))
    }

    /// Check if a public key is weak (e.g., in small subgroup)
    fn is_weak_public_key(&self, public_key: &BigUint) -> bool {
        // Check for 1 and p-1 (order 1 and 2 elements)
        if public_key == &BigUint::one() || public_key == &(&self.p - 1u32) {
            return true;
        }

        // For safe primes, also check if it's the generator of order q
        // This is a simplified check; real implementations need more thorough validation
        false
    }
}

/// Elliptic Curve Diffie-Hellman using X25519
///
/// X25519 is a modern, secure, and efficient ECDH implementation
pub struct X25519DiffieHellman {
    key_pair: Option<x25519::KeyPair>,
}

impl X25519DiffieHellman {
    /// Generate a new X25519 key pair
    pub fn new() -> Self {
        let key_pair = x25519::KeyPair::generate();
        Self {
            key_pair: Some(key_pair),
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.key_pair.as_ref().expect("Key pair not consumed").pk
    }

    /// Compute shared secret with another party's public key
    pub fn compute_shared_secret(mut self, other_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        let other_public = x25519::PublicKey::from_slice(other_public_key).map_err(|_| {
            CryptoError::InvalidPublicKey {
                reason: "Invalid X25519 public key".to_string(),
            }
        })?;

        let key_pair = self.key_pair.take().ok_or(CryptoError::InvalidInput {
            reason: "Private key already consumed".to_string(),
        })?;

        let shared_secret =
            other_public
                .dh(&key_pair.sk)
                .map_err(|_| CryptoError::InvalidPublicKey {
                    reason: "Failed to compute shared secret".to_string(),
                })?;

        Ok(*shared_secret)
    }
}

/// Authenticated Diffie-Hellman using signatures
///
/// This prevents man-in-the-middle attacks by signing the DH public keys
pub struct AuthenticatedDH {
    dh: X25519DiffieHellman,
    identity_key: Ed25519KeyPair,
}

impl AuthenticatedDH {
    /// Create a new authenticated DH instance
    pub fn new() -> Self {
        let identity_key = Ed25519KeyPair::from_seed(Seed::generate());
        let dh = X25519DiffieHellman::new();

        Self { dh, identity_key }
    }

    /// Get the public key and its signature
    pub fn get_signed_public_key(&self) -> ([u8; 32], Signature) {
        let public_key = self.dh.public_key_bytes();
        let signature = self
            .identity_key
            .sk
            .sign(&public_key, Some(Noise::generate()));
        (public_key, signature)
    }

    /// Verify and compute shared secret
    pub fn verify_and_compute_shared_secret(
        self,
        other_public_key: &[u8; 32],
        signature: &Signature,
        other_identity_key: &Ed25519PublicKey,
    ) -> Result<[u8; 32]> {
        // Verify the signature
        other_identity_key
            .verify(other_public_key, signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        // Compute shared secret
        self.dh.compute_shared_secret(other_public_key)
    }
}

/// Demonstrate the discrete logarithm problem
#[cfg(feature = "educational")]
pub mod discrete_log {
    use super::*;
    use num_traits::Zero;
    use std::time::Instant;

    /// Baby-step giant-step algorithm for solving discrete log
    ///
    /// Finds x such that g^x = h (mod p)
    /// This is exponentially hard for large groups!
    pub fn baby_step_giant_step(
        g: &BigUint,
        h: &BigUint,
        p: &BigUint,
        max_x: u64,
    ) -> Option<BigUint> {
        let m = (max_x as f64).sqrt().ceil() as u64;
        let mut table = std::collections::HashMap::new();

        // Baby steps: compute g^j for j = 0..m
        let mut g_j = BigUint::one();
        for j in 0..m {
            table.insert(g_j.clone(), j);
            g_j = (&g_j * g) % p;
        }

        // Giant steps: compute h * (g^-m)^i for i = 0..m
        let g_m = g.modpow(&BigUint::from(m), p);
        let g_m_inv = mod_inverse(&g_m, p)?;

        let mut gamma = h.clone();
        for i in 0..m {
            if let Some(&j) = table.get(&gamma) {
                let x = i * m + j;
                return Some(BigUint::from(x));
            }
            gamma = (&gamma * &g_m_inv) % p;
        }

        None
    }

    /// Compute modular inverse using extended Euclidean algorithm
    fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        let (gcd, x, _) = extended_gcd(a.clone(), m.clone());

        if gcd == BigUint::one() {
            // Handle negative x by adding m until positive
            let m_bigint = num_bigint::BigInt::from(m.clone());
            let x_bigint = x;
            let result = if x_bigint < num_bigint::BigInt::zero() {
                let positive_x = (x_bigint % &m_bigint + &m_bigint) % &m_bigint;
                BigUint::try_from(positive_x).ok()?
            } else {
                BigUint::try_from(x_bigint).ok()?
            };
            Some(result)
        } else {
            None
        }
    }

    /// Extended Euclidean algorithm
    fn extended_gcd(a: BigUint, b: BigUint) -> (BigUint, num_bigint::BigInt, num_bigint::BigInt) {
        use num_bigint::BigInt;
        use num_traits::Zero;

        let mut old_r = BigInt::from(a);
        let mut r = BigInt::from(b);
        let mut old_s = BigInt::one();
        let mut s = BigInt::zero();
        let mut old_t = BigInt::zero();
        let mut t = BigInt::one();

        while !r.is_zero() {
            let quotient = &old_r / &r;

            let temp_r = r.clone();
            r = old_r - &quotient * &r;
            old_r = temp_r;

            let temp_s = s.clone();
            s = old_s - &quotient * &s;
            old_s = temp_s;

            let temp_t = t.clone();
            t = old_t - &quotient * &t;
            old_t = temp_t;
        }

        (
            BigUint::try_from(old_r).unwrap_or_else(|_| BigUint::zero()),
            old_s,
            old_t,
        )
    }

    /// Demonstrate why discrete log is hard
    pub fn demonstrate_hardness() {
        println!("\n=== Discrete Logarithm Hardness Demo ===\n");

        // Small example where we can solve it
        let p = BigUint::from(2097593u32); // Small prime
        let g = BigUint::from(5u32); // Generator
        let x = BigUint::from(36u32); // Secret exponent
        let h = g.modpow(&x, &p); // Public value

        println!("Small group (p=97):");
        println!("  g = {}, h = g^x = {}", g, h);
        println!("  Finding x such that {}^x ≡ {} (mod {})", g, h, p);

        let start = Instant::now();
        if let Some(found_x) = baby_step_giant_step(&g, &h, &p, 100) {
            println!("  Found x = {} in {:?}", found_x, start.elapsed());
            assert_eq!(found_x, x);
        }

        println!("\nFor cryptographic sizes (4096-bit p), this would take");
        println!("longer than the age of the universe!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_dh() {
        let dh = ClassicDiffieHellman::new_rfc3526_2048();

        // Alice generates her key pair
        let alice_private = dh.generate_private_key();
        let alice_public = dh.compute_public_key(&alice_private);

        // Bob generates his key pair
        let bob_private = dh.generate_private_key();
        let bob_public = dh.compute_public_key(&bob_private);

        // Both compute shared secret
        let alice_shared = dh
            .compute_shared_secret(&alice_private, &bob_public)
            .unwrap();
        let bob_shared = dh
            .compute_shared_secret(&bob_private, &alice_public)
            .unwrap();

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_dh() {
        // Alice and Bob generate key pairs
        let alice = X25519DiffieHellman::new();
        let bob = X25519DiffieHellman::new();

        let alice_public = alice.public_key_bytes();
        let bob_public = bob.public_key_bytes();

        // Compute shared secrets
        let alice_shared = alice.compute_shared_secret(&bob_public).unwrap();
        let bob_shared = bob.compute_shared_secret(&alice_public).unwrap();

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_authenticated_dh() {
        let alice = AuthenticatedDH::new();
        let bob = AuthenticatedDH::new();

        // Get signed public keys
        let (alice_public, alice_sig) = alice.get_signed_public_key();
        let (bob_public, bob_sig) = bob.get_signed_public_key();

        // Get identity keys for verification (clone before moving alice and bob)
        let alice_identity = alice.identity_key.pk.clone();
        let bob_identity = bob.identity_key.pk.clone();

        // Verify and compute shared secrets
        let alice_shared = alice
            .verify_and_compute_shared_secret(&bob_public, &bob_sig, &bob_identity)
            .unwrap();

        let bob_shared = bob
            .verify_and_compute_shared_secret(&alice_public, &alice_sig, &alice_identity)
            .unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_weak_public_key_rejection() {
        let dh = ClassicDiffieHellman::new_rfc3526_2048();
        let private_key = dh.generate_private_key();

        // Try to use 1 as public key (should fail)
        let weak_key = BigUint::one();
        let result = dh.compute_shared_secret(&private_key, &weak_key);
        assert!(result.is_err());

        // Try to use p-1 as public key (should fail)
        let weak_key = &dh.p - 1u32;
        let result = dh.compute_shared_secret(&private_key, &weak_key);
        assert!(result.is_err());
    }
}
