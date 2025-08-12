# Applied Cryptography Starter Kit

A Rust crate providing educational implementations of cryptographic primitives covered in Part 1 of the [Applied Cryptography course at the American University of Beirut](https://appliedcryptography.page).

## Educational Purpose Only

This library is essentially a toy that offers **educational examples** of fundamental cryptographic concepts, making abstract theory concrete through working code. It includes **demonstrations** of both secure and insecure constructions, helping students understand why certain approaches fail and others succeed. Where applicable, the implementations use **constant-time operations** to illustrate proper cryptographic engineering practices, though these should not be relied upon for production use.

This library does not offer **production-ready security** - for real applications, use established libraries like `ring`, `rustcrypto`, or `sodiumoxide` that have undergone extensive review and testing. The educational code may not provide **side-channel resistance**, potentially leaking timing information that could compromise security in real-world scenarios. Some features are **simplified implementations** that omit advanced functionality to focus on core concepts. Most importantly, this code has **not been security audited** and should never be used where actual cryptographic security is required.

## Course Topics Covered

This starter kit implements cryptographic primitives from Part 1 of the Applied Cryptography course:

- **Topic 1.2**: One-Time Pad and Perfect Secrecy
- **Topic 1.4**: Pseudorandom Generators, Functions, and Permutations
- **Topic 1.5**: Block Cipher Modes (ECB, CBC, CTR)
- **Topic 1.6**: Collision-Resistant Hash Functions
- **Topic 1.7**: Diffie-Hellman Key Exchange
- **Topic 1.8**: Digital Signatures (ECDSA, EdDSA)

## Getting Started

### Running Examples

```bash
# Run all tests
cargo test

# Run with educational features (includes vulnerability demonstrations)
cargo test --features educational

# Run examples
cargo run --example basic_crypto

# Run examples with educational features (includes vulnerability demonstrations)
cargo run --example basic_crypto --features educational

# Build documentation
cargo doc --open
```

## Module Overview

### One-Time Pad (`one_time_pad`)

Demonstrates perfect secrecy and its limitations:

```rust
use applied_crypto_starter_kit::one_time_pad::{OneTimePad, generate_random_key};

let message = b"Secret Message!";
let key = generate_random_key(message.len()).unwrap();

let otp = OneTimePad::new(key);
let ciphertext = otp.encrypt(message).unwrap();
let plaintext = otp.decrypt(&ciphertext).unwrap();

assert_eq!(plaintext, message);
```

### Pseudorandom Primitives (`pseudorandom`)

PRGs, PRFs, and PRPs (block ciphers):

```rust
use applied_crypto_starter_kit::pseudorandom::{PseudorandomGenerator, PseudorandomFunction};

// Pseudorandom Generator
let seed = [42u8; 32];
let mut prg = PseudorandomGenerator::from_seed(seed);
let random_bytes = prg.generate(128);

// Pseudorandom Function (using HMAC)
let prf = PseudorandomFunction::new(vec![0x42; 32]);
let output = prf.evaluate(b"input data");
```

### Symmetric Encryption (`symmetric`)

Block cipher modes with security demonstrations:

```rust
use applied_crypto_starter_kit::symmetric::{aes_ctr, cbc, AuthenticatedEncryption};

// AES-CTR (CPA-secure stream cipher)
let key = [0u8; 32];
let plaintext = b"Hello, AES-CTR!";
let ciphertext = aes_ctr::encrypt(&key, plaintext).unwrap();
let decrypted = aes_ctr::decrypt(&key, &ciphertext).unwrap();

// Authenticated Encryption (CCA-secure)
let enc_key = [0x01u8; 32];
let mac_key = [0x02u8; 32];
let ae = AuthenticatedEncryption::new(enc_key, mac_key);
let secure_ciphertext = ae.encrypt(plaintext).unwrap();
```

### Hash Functions (`hashing`)

Various hash functions and applications:

```rust
use applied_crypto_starter_kit::hashing::{sha256, sha3, blake, password};

// Basic hashing
let hash = sha256::hash(b"Hello, World!");
println!("SHA-256: {}", hex::encode(hash));

// Password hashing with Argon2
let hashed = password::hash_password_argon2("my_password").unwrap();
let valid = password::verify_password_argon2("my_password", &hashed).unwrap();
assert!(valid);

// Proof of Work
use applied_crypto_starter_kit::hashing::ProofOfWork;
let pow = ProofOfWork::new(20); // 20 bits of difficulty
let (nonce, hash, duration) = pow.mine(b"Block data");
```

### Key Exchange (`key_exchange`)

Diffie-Hellman implementations:

```rust
use applied_crypto_starter_kit::key_exchange::{X25519DiffieHellman, ClassicDiffieHellman};

// Modern X25519 ECDH
let alice = X25519DiffieHellman::new();
let bob = X25519DiffieHellman::new();

let alice_public = alice.public_key_bytes();
let bob_public = bob.public_key_bytes();

let alice_shared = alice.compute_shared_secret(&bob_public).unwrap();
let bob_shared = bob.compute_shared_secret(&alice_public).unwrap();

assert_eq!(alice_shared, bob_shared);
```

### Digital Signatures (`signatures`)

EdDSA and ECDSA implementations:

```rust
use applied_crypto_starter_kit::signatures::{Ed25519, EcdsaP256};

// Ed25519 (recommended)
let signer = Ed25519::generate();
let message = b"Sign this message";
let signature = signer.sign(message);

assert!(signer.verify(message, &signature).is_ok());

// Verify with public key only
let public_key = signer.public_key_bytes();
assert!(Ed25519::verify_with_public_key(&public_key, message, &signature).is_ok());
```

### Message Authentication (`mac`)

HMAC and Poly1305:

```rust
use applied_crypto_starter_kit::mac::{HmacSha256, hmac_sha256};

// HMAC-SHA256
let hmac = HmacSha256::new(b"secret_key".to_vec());
let tag = hmac.compute(b"authenticated message");
assert!(hmac.verify(b"authenticated message", &tag).is_ok());

// Quick function
let tag = hmac_sha256(b"key", b"message");
```

### Key Derivation (`kdf`)

HKDF, PBKDF2, Argon2, and Scrypt:

```rust
use applied_crypto_starter_kit::kdf::{HkdfSha256, Pbkdf2, Argon2Kdf};

// HKDF for key derivation
let master_key = b"master secret";
let derived = HkdfSha256::derive(
    b"optional salt",
    master_key,
    b"application context",
    32 // output length
).unwrap();

// PBKDF2 for password-based keys
let pbkdf2 = Pbkdf2::new(100_000);
let key = pbkdf2.derive_sha256(b"password", b"salt", 32);
```
