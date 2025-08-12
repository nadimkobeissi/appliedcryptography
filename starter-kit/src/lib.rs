//! # Applied Cryptography Starter Kit
//!
//! A Rust crate providing educational implementations of cryptographic primitives covered in Part 1 of the [Applied Cryptography course at the American University of Beirut](https://appliedcryptography.page).
//!
//! ## Educational Purpose Only
//!
//! This library is essentially a toy that offers **educational examples** of fundamental cryptographic concepts, making abstract theory concrete through working code. It includes **demonstrations** of both secure and insecure constructions, helping students understand why certain approaches fail and others succeed. Where applicable, the implementations use **constant-time operations** to illustrate proper cryptographic engineering practices, though these should not be relied upon for production use.
//!
//! This library does not offer **production-ready security** - for real applications, use established libraries like `ring`, `rustcrypto`, or `sodiumoxide` that have undergone extensive review and testing. The educational code may not provide **side-channel resistance**, potentially leaking timing information that could compromise security in real-world scenarios. Some features are **simplified implementations** that omit advanced functionality to focus on core concepts. Most importantly, this code has **not been security audited** and should never be used where actual cryptographic security is required.
//!
//! ## Course Topics Covered
//!
//! This starter kit implements cryptographic primitives from Part 1 of the Applied Cryptography course:
//!
//! - **Topic 1.2**: One-Time Pad and Perfect Secrecy
//! - **Topic 1.4**: Pseudorandom Generators, Functions, and Permutations
//! - **Topic 1.5**: Block Cipher Modes (ECB, CBC, CTR)
//! - **Topic 1.6**: Collision-Resistant Hash Functions
//! - **Topic 1.7**: Diffie-Hellman Key Exchange
//! - **Topic 1.8**: Digital Signatures (ECDSA, EdDSA)
//!
//! ## Getting Started
//!
//! ### Running Examples
//!
//! ```bash
//! # Run all tests
//! cargo test
//!
//! # Run with educational features (includes vulnerability demonstrations)
//! cargo test --features educational
//!
//! # Run examples
//! cargo run --example basic_crypto
//!
//! # Run examples with educational features (includes vulnerability demonstrations)
//! cargo run --example basic_crypto --features educational
//!
//! # Build documentation
//! cargo doc --open
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export commonly used external types
pub use base64;
pub use hex;
pub use rand;

// Error handling
pub mod error;

// Core cryptographic modules aligned with course topics

/// Topic 1.2: The One-Time Pad and perfect secrecy
pub mod one_time_pad;

/// Topic 1.4: Pseudorandom generators, functions, and permutations
pub mod pseudorandom;

/// Topic 1.5: Symmetric encryption with block cipher modes
pub mod symmetric;

/// Topic 1.6: Collision-resistant hash functions
pub mod hashing;

/// Topic 1.7: Diffie-Hellman key exchange
pub mod key_exchange;

/// Topic 1.8: Elliptic curves and digital signatures
pub mod signatures;

/// Message authentication codes (MACs)
pub mod mac;

/// Key derivation functions (KDFs)
pub mod kdf;

/// Utility functions for working with cryptographic data
pub mod utils;

/// Educational examples demonstrating various attacks and vulnerabilities
#[cfg(feature = "educational")]

/// Prelude module for convenient imports
pub mod prelude {
    //! Common imports for working with the starter kit

    pub use crate::error::{CryptoError, Result};
    pub use crate::utils::{constant_time_compare, secure_random_bytes};
    pub use base64;
    pub use hex;
}

// Module documentation with examples

/// # Security Principles
///
/// This library demonstrates several fundamental security principles from the course:
///
/// ## Kerckhoffs's Principle
/// The security of a cryptosystem should depend only on the secrecy of the key,
/// not on the secrecy of the algorithm.
///
/// ## Computational Security
/// Modern cryptography relies on problems that are computationally hard to solve
/// without the secret key.
///
/// ## Provable Security
/// Security definitions and reduction proofs provide formal guarantees about
/// cryptographic constructions.

#[cfg(test)]
mod tests {

    #[test]
    fn test_library_compiles() {
        // Basic smoke test
        assert_eq!(2 + 2, 4);
    }
}

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
