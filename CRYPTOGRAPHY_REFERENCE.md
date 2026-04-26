# Cryptography Reference

> A comprehensive reference for cryptographic concepts, algorithms, attacks, and best practices.
> Maintained as part of the TeamStarWolf cybersecurity reference library.

---

## Table of Contents

1. [Symmetric Cryptography](#1-symmetric-cryptography)
2. [Asymmetric Cryptography](#2-asymmetric-cryptography)
3. [Hash Functions](#3-hash-functions)
4. [Public Key Infrastructure (PKI)](#4-public-key-infrastructure-pki)
5. [TLS/SSL Security](#5-tlsssl-security)
6. [Random Number Generation](#6-random-number-generation)
7. [Cryptographic Attacks](#7-cryptographic-attacks)
8. [Applied Cryptography](#8-applied-cryptography)
9. [Cryptographic Libraries and Implementation](#9-cryptographic-libraries-and-implementation)
10. [Compliance and Standards](#10-compliance-and-standards)

---

## 1. Symmetric Cryptography

Symmetric cryptography uses the same key for both encryption and decryption. It is generally much faster than asymmetric cryptography and is used for bulk data encryption. The challenge with symmetric systems is securely distributing the shared key.

### 1.1 AES (Advanced Encryption Standard)

AES (FIPS 197) is the most widely deployed symmetric cipher today. It replaced DES in 2001 after a public competition run by NIST. AES is a substitution-permutation network (SPN) operating on a 4x4 matrix of bytes called the **state**.

#### Key Sizes and Round Counts

| Key Size | Rounds | Security Level |
|----------|--------|----------------|
| 128-bit  | 10     | 128-bit        |
| 192-bit  | 12     | 192-bit        |
| 256-bit  | 14     | 256-bit        |

AES-128 is sufficient for most purposes. AES-256 is recommended when long-term security (post-quantum margins) is desired, since Grover's algorithm reduces its effective security to 128 bits.

#### Round Structure

Each AES round (except the last) consists of four transformations applied to the state:

**1. SubBytes (S-Box substitution)**
Each byte in the 4x4 state is replaced by a corresponding byte from a fixed 16x16 substitution table (the S-box). The S-box is constructed from the multiplicative inverse in GF(2^8) followed by an affine transformation, providing non-linearity to resist linear and differential cryptanalysis.

```
Before SubBytes:          After SubBytes:
19 a0 9a e9               d4 e0 b8 1e
3d f4 c6 f8     ------>   27 bf b4 41
e3 e2 8d 48               11 98 5d 52
be 2b 2a 08               ae f1 e5 30
```

**2. ShiftRows**
Each row of the state is cyclically shifted left by a different offset:
- Row 0: no shift
- Row 1: shift left by 1
- Row 2: shift left by 2
- Row 3: shift left by 3

This ensures that bytes from each column are spread across different columns in subsequent rounds, providing diffusion.

**3. MixColumns**
Each column of the state is treated as a polynomial over GF(2^8) and multiplied by a fixed polynomial `c(x) = 3x^3 + x^2 + x + 2`. This mixes bytes within each column, ensuring that changes in one byte affect the entire column. MixColumns is skipped in the final round.

**4. AddRoundKey**
Each byte of the state is XORed with the corresponding byte of the round key (derived from the key schedule). This is the only step that uses the secret key.

#### Key Schedule

The key schedule expands the original key into `Nb * (Nr + 1)` 32-bit words (where Nb=4 columns, Nr=rounds). It uses SubBytes via S-box lookups and round constants (Rcon) to prevent related-key attacks.

#### AES Security

- No practical attack better than brute force exists against full AES
- Related-key attacks exist against reduced-round variants in theoretical settings
- Biclique cryptanalysis (2011) reduces AES-128 brute force by a factor of ~4, still completely impractical
- Side-channel attacks (cache-timing, power analysis) are the primary real-world threat

---

### 1.2 Block Cipher Modes of Operation

A block cipher operates on fixed-size blocks (128 bits for AES). Modes of operation define how to encrypt data longer than one block.

#### ECB (Electronic Codebook)

Each block is encrypted independently with the same key.

```
C_i = E_K(P_i)
```

**The Penguin Problem:** ECB reveals patterns in plaintext. Identical plaintext blocks produce identical ciphertext blocks. The classic demonstration is encrypting a bitmap image of Tux the Linux penguin — the outline remains visible in the ciphertext because identical pixel blocks encrypt to identical ciphertext blocks.

ECB should **never** be used for encrypting more than one block of data.

#### CBC (Cipher Block Chaining)

Each plaintext block is XORed with the previous ciphertext block before encryption.

```
C_i = E_K(P_i XOR C_{i-1})
P_i = D_K(C_i) XOR C_{i-1}
C_0 = IV (Initialization Vector)
```

**IV Requirements:**
- Must be unpredictable (random) for each message
- Does not need to be secret, but must be unique
- Using a predictable IV (e.g., incrementing counter) allows chosen-plaintext attacks (BEAST)

**Padding:**
CBC requires input to be a multiple of the block size. PKCS#7 padding is typically used.

**CBC Decryption Parallelism:** CBC decryption can be parallelized (each block decrypts independently using the ciphertext), but CBC encryption is sequential.

**Error Propagation:** A single-bit error in a ciphertext block corrupts the corresponding plaintext block and flips one bit in the next plaintext block.

**Padding Oracle Attack (see Section 1.8)**

#### CTR (Counter Mode)

Converts a block cipher into a stream cipher. A counter value is encrypted to produce a keystream, which is XORed with the plaintext.

```
C_i = P_i XOR E_K(Nonce || Counter_i)
```

- Encryption and decryption are identical
- Fully parallelizable (both encryption and decryption)
- Random access to any block
- **Critical:** Counter values must never repeat with the same key. Reuse leads to two-time pad attacks.
- No padding required

#### GCM (Galois/Counter Mode)

GCM combines CTR mode encryption with a GHASH authentication tag, making it an Authenticated Encryption with Associated Data (AEAD) scheme.

```
Ciphertext = CTR_encrypt(Plaintext)
Tag = GHASH(AAD || Ciphertext) XOR E_K(IV || 0^32)
```

- Provides confidentiality AND integrity/authenticity
- Associated data (AAD) is authenticated but not encrypted (e.g., headers)
- Standard 96-bit nonce (IV)
- 128-bit authentication tag (can be truncated, but 128-bit recommended)
- Widely supported in hardware (CLMUL instruction on x86)

---

### 1.3 AES-GCM Deep Dive

#### Authentication Tag Generation

The authentication tag in GCM is generated using GHASH, which operates in GF(2^128) with the polynomial `x^128 + x^7 + x^2 + x + 1`.

```
GHASH(H, A, C):
  H = E_K(0^128)  # Hash key

  # Process AAD (A) in 128-bit blocks
  # Process ciphertext (C) in 128-bit blocks
  # Append length block: len(A) || len(C)
  # Each step: X_i = (X_{i-1} XOR block_i) * H  (in GF(2^128))

Tag = E_K(J_0) XOR S  # J_0 = nonce || 0^31 || 1
```

#### Nonce Reuse Catastrophe: The Forbidden Attack

If the same nonce is ever used with the same key in AES-GCM, confidentiality AND integrity are completely broken:

**What an attacker can recover with two messages using the same (Key, Nonce):**

```
C1 = P1 XOR Keystream
C2 = P2 XOR Keystream

C1 XOR C2 = P1 XOR P2  (plaintext XOR, completely breaks confidentiality)
```

**Authentication Tag Forgery (Forbidden Attack):**
Since the same H = E_K(0^128) and the same E_K(J_0) are used:
```
T1 XOR T2 = GHASH(H, A1, C1) XOR GHASH(H, A2, C2)
```
This allows solving for H (the GHASH key), and once H is known, arbitrary messages can be forged.

**Real-World Nonce Reuse Incidents:**
- WPA2 KRACK attack (2017): replay of nonce in 4-way handshake
- TLS: historically IV reuse issues in some implementations
- AWS S3 encryption bugs in older client libraries

**Mitigations:**
- Use random 96-bit nonces with key rotation when message count approaches 2^32
- Use deterministic nonce construction (e.g., message counter) with strict uniqueness guarantees
- Prefer AES-GCM-SIV (nonce-misuse resistant) for high-risk contexts

---

### 1.4 ChaCha20-Poly1305

ChaCha20-Poly1305 is a modern AEAD construction designed by Daniel J. Bernstein (djb), standardized in RFC 8439.

#### ChaCha20 Stream Cipher

ChaCha20 operates on a 512-bit (64-byte) state organized as a 4x4 matrix of 32-bit words:

```
State layout:
"expa"  "nd 3"  "2-by"  "te k"   <- Constants
Key[0]  Key[1]  Key[2]  Key[3]
Key[4]  Key[5]  Key[6]  Key[7]
Count   Nonce0  Nonce1  Nonce2
```

The core operation is the **quarter round**, applied 20 times (10 column rounds + 10 diagonal rounds):

```python
def quarter_round(a, b, c, d):
    a += b; d ^= a; d = rotate(d, 16)
    c += d; b ^= c; b = rotate(b, 12)
    a += b; d ^= a; d = rotate(d, 8)
    c += d; b ^= c; b = rotate(b, 7)
    return a, b, c, d
```

Uses only ARX (Add, Rotate, XOR) operations — no lookup tables, immune to cache-timing attacks.

#### Poly1305 MAC

Poly1305 is a one-time authenticator. For each message, a unique 256-bit key (r, s) is derived:
```
Tag = ((m_1 * r^n + m_2 * r^(n-1) + ... + m_n * r) + s) mod (2^130 - 5)
```

#### ChaCha20-Poly1305 Combined

1. Derive a 256-bit Poly1305 key from the first ChaCha20 keystream block (counter=0)
2. Encrypt plaintext with ChaCha20 (counter starting at 1)
3. Compute Poly1305 tag over AAD || ciphertext

#### Advantages Over AES in Software

| Feature | AES-GCM | ChaCha20-Poly1305 |
|---------|---------|-------------------|
| Hardware acceleration | Required for performance | Not required |
| Software speed (no HW) | ~100 MB/s | ~500+ MB/s |
| Cache-timing immunity | Needs AES-NI | Inherent (ARX) |
| Nonce size | 96-bit | 96-bit |
| Key size | 128 or 256-bit | 256-bit |
| Used in | TLS, storage | TLS (mobile), WireGuard |

ChaCha20-Poly1305 is preferred on devices without AES hardware acceleration (ARM mobile CPUs without AES-NI). TLS 1.3 mandates both TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256.

---

### 1.5 3DES (Triple DES)

3DES applies DES three times with different keys: `C = E_K3(D_K2(E_K1(P)))` (EDE mode).

**Key options:**
- 3TDEA (3-key): K1 ≠ K2 ≠ K3, effective security ~112 bits
- 2TDEA (2-key): K1 = K3 ≠ K2, effective security ~80 bits (deprecated)

#### Meet-in-the-Middle Attack

Double-DES (2DES) was rejected because of the meet-in-the-middle attack:
1. Encrypt all plaintext with all 2^56 possible K1 values → store in table
2. Decrypt all ciphertext with all 2^56 possible K2 values
3. Find matches → reduces effective security from 112 to ~57 bits

3DES with 3 independent keys resists this but 2-key 3DES is still theoretically vulnerable at ~2^112 effort.

#### SWEET32 Attack (CVE-2016-2183)

3DES uses a 64-bit block size. With a 64-bit block cipher, the **birthday bound** is 2^32 blocks (~32 GB). After this volume:
- Collisions in ciphertext blocks become likely
- In CBC mode, an attacker observing ~32 GB of traffic can recover plaintext blocks

**Impact:** HTTPS sessions with long-lived connections (keep-alive) could leak session cookies.

**Mitigation:**
- Limit 3DES connections to 2^20 blocks per session key
- Migrate to AES (TLS 1.3 dropped 3DES entirely)
- NIST deprecated 3DES in 2017, disallowed after 2023

---

### 1.6 Key Derivation Functions (KDFs)

KDFs derive cryptographic keys from passwords or other input material. Dedicated password hashing KDFs add computational cost to resist brute-force attacks.

#### PBKDF2 (Password-Based Key Derivation Function 2)

Defined in RFC 8018. Applies an HMAC iteratively:
```
DK = PRF(Password, Salt || INT(i))  [repeated c iterations]
```

**Parameters:**
- Salt: 16+ bytes, random, stored alongside hash
- Iterations: NIST SP 800-132 recommends ≥600,000 for HMAC-SHA256 (2023)
- Output length: configurable

**Weakness:** Memory-hard (not). PBKDF2 can be efficiently parallelized on GPUs. An attacker with a GPU cluster can test billions of passwords/second.

**Still required for:** FIPS-compliant systems (FIPS 140-3 approved)

#### bcrypt

Based on the Blowfish cipher. Designed to be memory-hard and CPU-intensive.

```python
import bcrypt
salt = bcrypt.gensalt(rounds=12)  # cost factor 2^12 = 4096 iterations
hashed = bcrypt.hashpw(password.encode(), salt)
```

**Parameters:**
- Cost factor: 10-12 recommended for interactive logins (adjustable over time)
- Output: 60-character string including salt and cost factor
- Maximum password length: 72 bytes (silently truncates)

**Weakness:** 72-byte password limit; limited parallelism resistance on GPU vs. Argon2.

#### scrypt

Designed by Colin Percival (2009). Memory-hard: requires large amounts of RAM.

```
scrypt(N, r, p, dkLen):
  N = CPU/memory cost parameter (e.g., 2^14 to 2^20)
  r = block size (8)
  p = parallelization parameter (1)
```

**Recommended parameters (2024):**
- Interactive: N=2^14, r=8, p=1 (16 MB RAM, ~100ms)
- Sensitive: N=2^20, r=8, p=1 (1 GB RAM, ~5s)

#### Argon2id (Recommended)

Winner of the Password Hashing Competition (2015). Three variants:
- **Argon2d:** Data-dependent memory access (resist GPU/ASIC, vulnerable to side-channel)
- **Argon2i:** Data-independent memory access (resist side-channel, less GPU-resistant)
- **Argon2id:** Hybrid of both (recommended for general use)

**OWASP Recommended Parameters (2024):**
```
# Minimum (interactive login):
Argon2id, m=19456 (19 MB), t=2 iterations, p=1

# High security (sensitive data):
Argon2id, m=65536 (64 MB), t=3 iterations, p=4

# Very high security:
Argon2id, m=262144 (256 MB), t=4 iterations, p=4
```

**Python example:**
```python
import argon2
ph = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16
)
hash = ph.hash("password")
ph.verify(hash, "password")
```

**Comparison Table:**

| KDF | Memory-Hard | GPU-Resistant | FIPS Approved | Recommended Use |
|-----|-------------|---------------|---------------|-----------------|
| PBKDF2 | No | No | Yes | Legacy/FIPS-required systems |
| bcrypt | Partial | Partial | No | Web apps (widely supported) |
| scrypt | Yes | Yes | No | General use |
| Argon2id | Yes | Yes | No | New applications (preferred) |

---

### 1.7 Padding Schemes

#### PKCS#7 Padding

Used with block ciphers. Pads to block boundary by appending N bytes each with value N.

```
Plaintext: DE AD BE EF               (4 bytes)
Block size: 16 bytes
Padding needed: 12 bytes
Padded: DE AD BE EF 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C
```

If data is already a multiple of block size, a full extra block of padding is added.

#### OAEP (Optimal Asymmetric Encryption Padding)

Used with RSA encryption (PKCS#1 v2.x). Provides semantic security and resists chosen-ciphertext attacks:

```
EM = 0x00 || maskedSeed || maskedDB
maskedSeed = seed XOR MGF(maskedDB)
maskedDB   = DB XOR MGF(seed)
DB = lHash || PS || 0x01 || M
```

Where MGF is Mask Generation Function (typically MGF1 with SHA-256). Always use OAEP over PKCS#1 v1.5 for new applications.

#### PSS (Probabilistic Signature Scheme)

Used with RSA signatures (PKCS#1 v2.1). Adds randomness and a salt to resist existential forgery attacks. More secure than PKCS#1 v1.5 signatures.

---

### 1.8 Padding Oracle Attacks

#### CBC Padding Oracle

A **padding oracle** is any system that reveals whether decrypted data has valid PKCS#7 padding — even just through different error messages or timing.

**Attack mechanism (Vaudenay, 2002):**

Given ciphertext block C_i, the attacker wants to recover P_i. They know:
```
P_i = D_K(C_i) XOR C_{i-1}
```

The attacker modifies the last byte of C_{i-1} and sends modified ciphertext to the oracle:
1. Try all 256 values for the last byte of C'_{i-1}
2. When the oracle says "valid padding," P'_i ends in 0x01
3. Deduce: D_K(C_i)[-1] = 0x01 XOR C'_{i-1}[-1]
4. Recover the original plaintext byte: P_i[-1] = D_K(C_i)[-1] XOR C_{i-1}[-1]

This can decrypt any CBC-encrypted message with ~128 oracle calls per byte.

**Real-world examples:** ASP.NET (MS10-070), Apache XML Security, numerous Java web frameworks.

**Mitigation:**
- Use AEAD (GCM) instead of CBC
- Encrypt-then-MAC (always verify MAC before decryption)
- Use constant-time comparison for padding checks

#### POODLE (Padding Oracle On Downgraded Legacy Encryption)

CVE-2014-3566. A protocol downgrade attack against SSL 3.0's CBC implementation.

SSL 3.0's padding is only partially specified: the last byte gives padding length, but intermediate padding bytes can be anything. This allows a padding oracle even without implementation errors.

**Attack steps:**
1. Attacker forces downgrade to SSL 3.0 (via connection failures)
2. Uses MITM to inject chosen-boundary requests
3. Exploits the padding oracle to decrypt session cookies

**Mitigation:** Disable SSL 3.0. TLS_FALLBACK_SCSV prevents downgrade attacks.

---

## 2. Asymmetric Cryptography

Asymmetric (public-key) cryptography uses a mathematically related key pair: a public key (freely distributed) and a private key (kept secret). Security relies on mathematical problems believed to be hard (factoring, discrete log).

### 2.1 RSA

RSA (Rivest-Shamir-Adleman, 1977) is based on the integer factorization problem.

#### Key Generation

```
1. Choose large primes p, q (each ~2048 bits for RSA-4096)
2. Compute n = p * q  (modulus, public)
3. Compute φ(n) = (p-1)(q-1)  (Euler's totient, or λ(n) = lcm(p-1, q-1) preferred)
4. Choose e: 1 < e < φ(n), gcd(e, φ(n)) = 1  (public exponent, typically 65537)
5. Compute d: d * e ≡ 1 (mod φ(n))  (private exponent, d = e^(-1) mod φ(n))
```

Public key: (n, e) | Private key: (n, d) or (p, q, d, dp, dq, qInv)

#### Encryption and Decryption

```
Encryption (public key):  C = M^e mod n
Decryption (private key): M = C^d mod n
```

In practice, OAEP padding must be used. Raw RSA (textbook RSA) is malleable and insecure.

#### Digital Signatures

```
Sign (private key):   S = H(M)^d mod n  (sign hash of message)
Verify (public key):  H(M) == S^e mod n
```

In practice, PSS padding must be used.

#### CRT Optimization (Chinese Remainder Theorem)

Decryption/signing with the private key requires modular exponentiation mod n (~2048-4096 bits). CRT speeds this up ~4x by working mod p and mod q separately:

```
dp = d mod (p-1)
dq = d mod (q-1)
qInv = q^(-1) mod p

m1 = c^dp mod p
m2 = c^dq mod q
h = qInv * (m1 - m2) mod p
m = m2 + h * q
```

**CRT Fault Attack:** If fault injection causes an error in m1 or m2, gcd(faulty_signature - correct_signature, n) = p or q, completely breaking the key. Implementations must verify the result before returning.

#### Recommended RSA Key Sizes (NIST SP 800-57)

| Security Level | RSA Key Size | Valid Until |
|---------------|--------------|-------------|
| 80-bit | 1024-bit | Deprecated |
| 112-bit | 2048-bit | 2030 |
| 128-bit | 3072-bit | 2030+ |
| 192-bit | 7680-bit | Long-term |
| 256-bit | 15360-bit | Long-term |

---

### 2.2 RSA Vulnerabilities

#### Small Public Exponent Attacks

If e=3 and the same message M is sent to 3 different recipients (Håstad's broadcast attack):
```
C1 = M^3 mod n1
C2 = M^3 mod n2
C3 = M^3 mod n3

By CRT: X = M^3 mod (n1*n2*n3)
Since M^3 < n1*n2*n3, X = M^3 exactly
M = cube_root(X)
```

Mitigation: Always use proper padding (OAEP).

#### Common Factor Attack

If two RSA moduli n1 = p*q1 and n2 = p*q2 share a prime factor p:
```
gcd(n1, n2) = p
```

This immediately factors both keys. In 2012, Heninger et al. computed GCDs of millions of public keys from internet scans and found ~0.2% of keys shared factors due to poor entropy during key generation (often embedded devices).

#### PKCS#1 v1.5 Bleichenbacher Attack (1998)

RSA encryption with PKCS#1 v1.5 padding:
```
EM = 0x00 || 0x02 || PS || 0x00 || M
```

A **PKCS oracle** that reveals whether decryption produces a message starting with 0x00 0x02 allows adaptive chosen-ciphertext attack. Using ~1 million queries, the attacker can decrypt arbitrary messages.

**ROBOT Attack (2017):** Discovered that 8 of the top 100 HTTPS sites were vulnerable to variants of this 19-year-old attack.

**Mitigation:** Use OAEP for encryption. Never use PKCS#1 v1.5 for new code.

#### RSA Timing Attacks

Montgomery multiplication has timing variations based on input values. An attacker measuring decryption time across many queries can recover the private key. Mitigations include:
- Blinding: multiply input by r^e before decryption, unblind after
- Constant-time implementations

---

### 2.3 Diffie-Hellman Key Exchange

DH (1976) allows two parties to establish a shared secret over an insecure channel without prior shared secrets.

#### Discrete Logarithm Problem (DLP)

Given g, p, and g^a mod p, finding a is computationally infeasible for large p. This is the DLP in the multiplicative group Z_p*.

#### Protocol

```
Public parameters: large prime p, generator g (public)
Alice: choose secret a, compute A = g^a mod p, send A
Bob:   choose secret b, compute B = g^b mod p, send B
Shared secret: Alice computes K = B^a mod p = g^(ab) mod p
               Bob computes K = A^b mod p = g^(ab) mod p
```

#### Ephemeral DH (DHE)

Standard DH uses static keys, providing no forward secrecy. DHE generates fresh key pairs for each session:
- If the server's long-term private key is compromised later, past session keys remain secret
- DHE is slower but provides Perfect Forward Secrecy (PFS)

#### Parameter Selection

For DH in TLS, parameter choice matters:
- **Minimum:** 2048-bit prime (1024-bit was broken by Logjam)
- **Recommended:** Use RFC 3526 or RFC 7919 well-known groups (ffdhe2048, ffdhe3072, ffdhe4096)
- **Avoid:** Custom DH parameters, especially 512/768/1024-bit parameters
- **Prefer:** ECDHE over DHE (smaller keys, faster operations, same security)

---

### 2.4 DH Vulnerabilities

#### Logjam Attack (CVE-2015-4000)

A downgrade attack on TLS that forced DHE to use 512-bit "export-grade" DH parameters. An offline precomputation against common 512-bit primes (shared by ~80% of TLS servers using export DH) allowed decryption of ~8.4% of HTTPS traffic.

**Extended impact:** The NSA may have precomputed discrete logs for the most common 1024-bit DH primes, potentially enabling mass surveillance of SSH and IPsec traffic.

**Mitigation:**
- Disable export cipher suites
- Use 2048-bit minimum DH parameters
- Prefer ECDHE

#### Small Subgroup Attacks

In groups with composite order, an attacker can send a public key from a small subgroup to force the shared secret to be in that subgroup. With a small subgroup of order q, only q possible shared secrets exist (easily brute-forced).

**Mitigation:** Validate that received public keys have the correct order. Use safe primes (where p = 2q + 1, so the group has prime order q). ECDH over prime-order curves is naturally resistant.

---

### 2.5 Elliptic Curve Cryptography (ECC)

ECC provides equivalent security to RSA with much smaller key sizes, based on the Elliptic Curve Discrete Logarithm Problem (ECDLP).

#### Elliptic Curve Groups

An elliptic curve over a prime field F_p is defined by:
```
y^2 = x^3 + ax + b  (mod p)
```

The set of points (x, y) satisfying this equation, plus a "point at infinity" O, forms an abelian group under a special addition operation.

**Point addition:** Given points P and Q, the line through P and Q intersects the curve at a third point R; the sum P+Q = -R (reflection over x-axis).

**Scalar multiplication:** kP = P + P + ... + P (k times). This is done efficiently with double-and-add.

**ECDLP:** Given P and kP, finding k is hard. This is the basis of ECC security.

#### ECDH (Elliptic Curve Diffie-Hellman)

```
Public: curve parameters, base point G
Alice: private key a, public key A = aG, sends A
Bob:   private key b, public key B = bG, sends B
Shared: Alice computes aB = a(bG) = abG
        Bob computes bA = b(aG) = abG
```

#### ECDSA (Elliptic Curve Digital Signature Algorithm)

**Sign:**
```
1. Generate random k (nonce)
2. Compute (x, y) = kG
3. r = x mod n
4. s = k^(-1) * (H(m) + r*d) mod n
Signature: (r, s)
```

**Verify:**
```
1. w = s^(-1) mod n
2. u1 = H(m) * w mod n
3. u2 = r * w mod n
4. (x, y) = u1*G + u2*Q
5. Valid if r == x mod n
```

#### Ed25519

Edwards-curve Digital Signature Algorithm using Curve25519. Designed by Bernstein et al. to avoid subtle implementation issues.

**Advantages:**
- Deterministic signatures (no random k needed, avoids nonce reuse)
- Fast (batch verification possible)
- Small keys and signatures (32-byte public key, 64-byte signature)
- Immune to timing attacks by design

---

### 2.6 Curve Comparison: secp256k1 vs P-256 vs Curve25519

| Property | secp256k1 | P-256 (secp256r1) | Curve25519 |
|----------|-----------|-------------------|------------|
| Standard | SECG | NIST / FIPS | Bernstein |
| Equation | Short Weierstrass | Short Weierstrass | Montgomery |
| Field size | 256-bit | 256-bit | 255-bit |
| Security level | ~128-bit | ~128-bit | ~128-bit |
| Primary use | Bitcoin/Ethereum | TLS, FIDO2 | WireGuard, Signal |
| NIST-endorsed | No | Yes | No |
| Twist-secure | No | No | Yes |
| Constant-time ease | Moderate | Moderate | Excellent |
| Suspicious constants | No | Possible* | No |

*P-256 uses unexplained "random-looking" constants (seed = c49d3608 86e70493 6a6678e1...) chosen by NSA, raising concerns about potential backdoors. No vulnerability has been demonstrated.

**secp256k1** has a=0, making it slightly faster for some operations. Used exclusively in cryptocurrencies.

**Curve25519** was designed to maximize security and implementation simplicity. Every implementation detail is justified with security reasoning. Recommended for new applications.

---

### 2.7 ECDSA Nonce Reuse: PlayStation 3 Attack

If the same nonce k is used in two ECDSA signatures over the same key:

```
s1 = k^(-1) * (H(m1) + r * d) mod n
s2 = k^(-1) * (H(m2) + r * d) mod n
```

Since r = (kG).x is the same for both:
```
s1 - s2 = k^(-1) * (H(m1) - H(m2)) mod n
k = (H(m1) - H(m2)) * (s1 - s2)^(-1) mod n
d = (s1 * k - H(m1)) * r^(-1) mod n
```

**PlayStation 3 (2010):** Sony used a constant k for all firmware signing. Researchers extracted the private signing key from two signatures, enabling arbitrary PS3 code signing. This broke the entire PS3 security model.

**Mitigation:** Use RFC 6979 deterministic ECDSA (k derived from private key and message via HMAC-DRBG). Or use Ed25519 which avoids the nonce entirely.

---

### 2.8 ElGamal Encryption

ElGamal is based on the DLP and has useful homomorphic properties.

**Encryption:**
```
Public key: (p, g, h = g^x mod p)  where x is private key
Random r: c1 = g^r mod p, c2 = m * h^r mod p
Ciphertext: (c1, c2)
```

**Decryption:**
```
m = c2 * c1^(-x) mod p = c2 / h^r mod p
```

**Multiplicative homomorphism:**
```
Enc(m1) * Enc(m2) = (g^r1 * g^r2, m1*h^r1 * m2*h^r2)
                  = Enc(m1 * m2)  (with fresh randomness)
```

This allows computing the product of two encrypted values without decryption. Used in some e-voting systems.

---

## 3. Hash Functions

A cryptographic hash function H maps arbitrary-length input to a fixed-length digest with three security properties:
- **Preimage resistance:** Given h, hard to find m such that H(m) = h
- **Second preimage resistance:** Given m1, hard to find m2 ≠ m1 such that H(m1) = H(m2)
- **Collision resistance:** Hard to find any m1 ≠ m2 such that H(m1) = H(m2)

### 3.1 MD5

MD5 produces a 128-bit digest. Completely broken for collision resistance.

**Collision attacks:**
- Wang and Yu (2004): found MD5 collisions in hours on a laptop
- Identical-prefix collisions: construct two files sharing a prefix with the same MD5
- Chosen-prefix collisions: construct a collision with arbitrary chosen prefixes

#### Flame Malware Certificate Forgery (2012)

Flame used a chosen-prefix MD5 collision to forge a Microsoft code-signing certificate:
1. Obtained a legitimate certificate from Microsoft's Terminal Server Licensing CA (which used MD5)
2. Constructed a malicious CA certificate that had the same MD5 as the legitimate cert
3. Used the forged CA certificate to sign Flame as a legitimate Microsoft update

**Impact:** Flame propagated as an authentic Windows Update on fully-patched Windows systems.

MD5 must never be used for:
- Digital signatures
- Certificate generation
- Security-sensitive integrity checks

MD5 may still be used for non-security checksums (file deduplication, hash tables).

---

### 3.2 SHA-1

SHA-1 produces a 160-bit digest. Collision resistance broken.

**Timeline:**
- 2004: Wang et al. theoretical attack, 2^69 operations
- 2005: Attack improved to 2^63 operations
- 2017: **SHAttered** — first practical identical-prefix SHA-1 collision (Google/CWI Amsterdam)
  - Cost: ~$75,000 in cloud compute
  - Produced two different PDF files with identical SHA-1

**Migration urgency:** Chrome/Firefox dropped SHA-1 certificate support in 2017. All code signing systems should have migrated by now. Git announced SHA-1 to SHA-256 transition (ongoing).

Git's internal use of SHA-1 (for object naming, not security) was a separate concern — git uses SHA-1 in a hash-ID context where second preimage resistance matters more than collision resistance.

---

### 3.3 SHA-256/384/512 (SHA-2)

SHA-2 family uses the **Merkle-Damgård construction**.

#### Merkle-Damgård Construction

```
Message M → pad to multiple of block size → split into blocks M1, M2, ..., Mn
H0 = IV (fixed initialization vector)
Hi = compress(H_{i-1}, Mi)
Output = Hn
```

The compression function is the core — SHA-256 uses 64 rounds of a complex mixing function.

**SHA-2 variants:**

| Algorithm | Digest | Block | State | Rounds |
|-----------|--------|-------|-------|--------|
| SHA-224 | 224-bit | 512-bit | 256-bit | 64 |
| SHA-256 | 256-bit | 512-bit | 256-bit | 64 |
| SHA-384 | 384-bit | 1024-bit | 512-bit | 80 |
| SHA-512 | 512-bit | 1024-bit | 512-bit | 80 |
| SHA-512/256 | 256-bit | 1024-bit | 512-bit | 80 |

#### Length Extension Attacks

Merkle-Damgård construction is vulnerable to length extension attacks. Given H(secret || message), an attacker can compute H(secret || message || padding || extension) without knowing `secret`.

**Vulnerable patterns:**
```python
# WRONG - vulnerable to length extension
mac = sha256(secret + message)

# CORRECT
mac = hmac.new(secret, message, sha256)
```

Affected: SHA-1, SHA-256, SHA-512, MD5 (all MD/SHA-2 variants)
Not affected: SHA-3, BLAKE2, HMAC-based constructions

---

### 3.4 SHA-3 (Keccak)

SHA-3 won the NIST hash competition in 2012. Uses the **sponge construction** instead of Merkle-Damgård.

#### Sponge Construction

```
State: b = r + c bits (rate r + capacity c)
Absorbing phase: XOR message blocks into rate portion, apply permutation f
Squeezing phase: Output rate portion, apply permutation f, repeat

SHA3-256: r=1088, c=512, output=256 bits
```

The permutation f is **Keccak-f[1600]** — 24 rounds of 5 steps (θ, ρ, π, χ, ι) over a 5x5x64 bit array.

**Key properties:**
- Inherently resistant to length extension attacks (capacity c is never exposed)
- Different internal structure from SHA-2 (independent security assurance)
- SHAKE128/SHAKE256: variable-length output (XOFs — extendable output functions)

**SHA-3 performance:** Slower than SHA-256 in software on x86 without dedicated hardware. SHA-3 shines on hardware and constrained devices.

---

### 3.5 BLAKE2 / BLAKE3

BLAKE2 (2012) and BLAKE3 (2020) offer excellent performance with strong security.

#### BLAKE2

Derived from BLAKE (SHA-3 finalist). Uses ChaCha-like design.
- **BLAKE2b:** Optimized for 64-bit platforms, 1-64 byte output
- **BLAKE2s:** Optimized for 32-bit/embedded, 1-32 byte output

Performance: 2-3x faster than SHA-256 on modern CPUs without hardware acceleration.

Features: Built-in keying (replaces HMAC), salt, personalization parameters.

#### BLAKE3

Massively parallel Merkle tree construction. Speed highlights:
- 14 GB/s on a single core (with SIMD)
- Arbitrarily parallelizable across multiple cores
- Same core compression function as BLAKE2s
- Extendable output (XOF like SHAKE)
- Security: 128-bit for collision resistance (256-bit key security)

```python
import blake3
h = blake3.blake3(b"data").hexdigest()
# Keyed mode
h = blake3.blake3(b"data", key=b"k"*32).hexdigest()
```

---

### 3.6 Hash Function Use Cases

| Use Case | Recommended | Avoid |
|----------|-------------|-------|
| Password hashing | Argon2id, bcrypt, scrypt | SHA-*, MD5, BLAKE |
| Data integrity | SHA-256, SHA-3, BLAKE3 | MD5 (integrity only) |
| Digital signatures | SHA-256, SHA-384, SHA-512 | MD5, SHA-1 |
| HMAC | SHA-256, SHA-512, BLAKE2 | MD5 |
| File checksums | SHA-256, BLAKE3 | MD5 (but acceptable for non-security) |
| PRF/KDF | HMAC-SHA256, HKDF | Direct hash |
| Merkle trees | SHA-256, BLAKE3 | MD5, SHA-1 |

**Why not use SHA-256 for passwords?** SHA-256 is designed to be fast (billions of hashes/second on GPUs). Password hashing requires intentional slowness and memory-hardness. Always use Argon2id, bcrypt, or scrypt for passwords.

---

### 3.7 Merkle Trees

A Merkle tree is a binary tree where each leaf node contains a hash of data, and each internal node contains a hash of its two children.

```
         Root = H(H12 || H34)
        /                    \
   H12 = H(H1||H2)      H34 = H(H3||H4)
   /         \            /          \
H1=H(d1)  H2=H(d2)  H3=H(d3)  H4=H(d4)
```

#### Inclusion Proof

To prove d2 is in the tree, provide:
- H(d2) (leaf hash)
- Sibling nodes along the path: H1, H34
- Verifier recomputes: H(H1||H(d2)) = H12, H(H12||H34) = Root
- Compare with known Root

Proof size: O(log n) hashes for n leaves.

#### Applications

- **Git:** Each commit references a Merkle tree of the repository state
- **Bitcoin/Ethereum:** Transaction Merkle trees in block headers enable SPV (Simplified Payment Verification)
- **Certificate Transparency (CT):** Merkle trees of certificate logs enable efficient inclusion proofs
- **IPFS:** Content-addressed DAG using SHA-256
- **ZFS/Btrfs:** Filesystem integrity via Merkle trees

---

### 3.8 HMAC

HMAC (Hash-based Message Authentication Code) provides a secure MAC using a hash function.

```
HMAC(K, m) = H( (K XOR opad) || H( (K XOR ipad) || m ) )
opad = 0x5C repeated to block size
ipad = 0x36 repeated to block size
```

If key > block size, it is first hashed. If key < block size, it is zero-padded.

**Security:** HMAC is a PRF even if the underlying hash has length extension vulnerabilities, because the inner hash is double-processed.

#### Timing-Safe Comparison

When verifying HMACs, use constant-time comparison to prevent timing oracles:

```python
import hmac

# WRONG - short-circuit evaluation reveals match length
if computed_mac == received_mac:
    ...

# CORRECT - constant-time
if hmac.compare_digest(computed_mac, received_mac):
    ...
```

**HKDF (HMAC-based Key Derivation Function):**
```
HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)  → PRK
HKDF-Expand(PRK, info, L) = T1 || T2 || ...      → OKM
  T1 = HMAC-Hash(PRK, "" || info || 0x01)
  T2 = HMAC-Hash(PRK, T1 || info || 0x02)
  ...
```

Used in TLS 1.3, Signal Protocol, and many modern protocols.

---

## 4. Public Key Infrastructure (PKI)

PKI is the set of roles, policies, hardware, software, and procedures needed to create, manage, distribute, use, store, and revoke digital certificates.

### 4.1 X.509 Certificate Structure

An X.509 v3 certificate contains:

```
Certificate:
  tbsCertificate (To Be Signed Certificate):
    version: v3 (2)
    serialNumber: unique integer
    signature: algorithm (e.g., sha256WithRSAEncryption)
    issuer: Distinguished Name (C=US, O=Let's Encrypt, CN=R3)
    validity:
      notBefore: 2024-01-01T00:00:00Z
      notAfter:  2024-04-01T00:00:00Z
    subject: Distinguished Name
    subjectPublicKeyInfo:
      algorithm: rsaEncryption
      subjectPublicKey: [public key bits]
    extensions:
      subjectAltName (SAN): DNS:example.com, DNS:www.example.com
      keyUsage: digitalSignature, keyEncipherment
      extendedKeyUsage: serverAuth, clientAuth
      basicConstraints: CA:FALSE
      authorityInfoAccess (AIA):
        OCSP: http://ocsp.example.ca/
        caIssuers: http://certs.example.ca/intermediate.crt
      cRLDistributionPoints (CDP): http://crl.example.ca/crl.pem
      subjectKeyIdentifier: [key hash]
      authorityKeyIdentifier: [issuer key hash]
      certificateTransparency: [SCT list]
  signatureAlgorithm: sha256WithRSAEncryption
  signature: [CA's signature over tbsCertificate DER encoding]
```

#### SAN (Subject Alternative Name)

Modern certificates use SAN (not CN) for hostname validation. Chrome deprecated CN-only matching in 2017. A single certificate can include:
- DNS names: `DNS:example.com`, `DNS:*.example.com`
- IP addresses: `IP:192.0.2.1`
- Email addresses: `email:user@example.com`
- URIs

---

### 4.2 Certificate Lifecycle

```
Key Generation → CSR Creation → CA Validation → Certificate Issuance
     ↓                                                    ↓
Private key                                      Deploy to server
stored securely                                         ↓
                                               Monitor expiration
                                                        ↓
                                         Renew (before expiry) or Revoke
```

**Certificate Signing Request (CSR):**
```bash
openssl req -new -newkey rsa:4096 -keyout server.key -out server.csr \
  -subj "/C=US/ST=CA/L=SF/O=Example Inc/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
```

**Validation levels:**
- **DV (Domain Validation):** Proves control of domain. Automated, minutes. No identity info.
- **OV (Organization Validation):** Proves domain + organization identity. 1-3 days.
- **EV (Extended Validation):** Strict identity verification. Browser used to show green bar (removed in 2019).

---

### 4.3 CA Hierarchy

```
Root CA (self-signed, offline in HSM)
  ├── Intermediate CA 1 (online, constrained)
  │     ├── Issuing CA A (signs end-entity certs)
  │     └── Issuing CA B
  └── Intermediate CA 2
        └── Issuing CA C
```

**Root CA:** Kept offline in HSMs in secure facilities. Signs intermediate CA certificates and CRLs only. Long validity (20+ years).

**Intermediate CA:** Online, issues end-entity certificates. If compromised, can be revoked without invalidating root. Typically 5-10 year validity.

**Cross-certification:** Two root CAs can cross-certify each other, extending trust paths.

**Certificate Pinning (in CA context):** Browsers have built-in root stores. Mozilla NSS, Chrome Root Store, Apple Root Store, Microsoft Root Program — each with different inclusion requirements.

---

### 4.4 Certificate Revocation

#### CRL (Certificate Revocation List)

Signed list of revoked certificate serial numbers, published by the CA.
```
CRL fields:
- thisUpdate: time of CRL generation
- nextUpdate: time when next CRL will be published
- revokedCertificates list:
    serialNumber, revocationDate, reasonCode
```

**Problems:**
- Large files (major CAs have multi-MB CRLs)
- Stale data (updated every 24-72 hours)
- Soft-fail: browsers often ignore CRL fetch failures
- Privacy: reveals which sites a user visits

#### OCSP (Online Certificate Status Protocol)

Real-time certificate status query:
```
Request: issuerNameHash, issuerKeyHash, serialNumber
Response: good / revoked / unknown
Status validity: typically 7-14 days
```

**OCSP Stapling:** Server includes pre-fetched OCSP response in TLS handshake. Solves privacy and performance issues. Browser verifies the stapled response. Must-Staple extension requires browsers to reject certificates without a valid staple.

#### CRLite / CRLSets

Firefox (CRLite) and Chrome (CRLSets) use bloom filter cascades to encode all revoked certificates in a compact format (~1 MB) distributed via browser updates.

---

### 4.5 Certificate Transparency (CT)

CT (RFC 9162) is a public, append-only log of all issued certificates, designed to detect misissued certificates.

#### Log Structure

CT logs are Merkle hash trees. All certificates from participating CAs are submitted to CT logs before issuance.

**Signed Certificate Timestamp (SCT):** Proof that a certificate was submitted to a CT log. Required by Chrome since 2018.

#### Inclusion Proof

To verify a certificate is in a CT log:
1. Client has the certificate (leaf hash) and the signed tree head (STH)
2. Log provides a Merkle audit proof (sibling hashes along the path)
3. Client recomputes the root hash and compares with STH

**Monitoring:** Anyone can monitor CT logs for certificates issued for their domains. Services like crt.sh provide CT log search.

---

### 4.6 ACME Protocol (Let's Encrypt)

ACME (RFC 8555) automates certificate issuance and renewal.

#### ACME Flow

```
1. Account creation (JWKS-based)
2. Order for domain names
3. Authorization challenges (prove domain control)
4. Certificate issuance
5. Automatic renewal (certbot --renew)
```

#### Challenge Types

**HTTP-01:** Place a token at `http://domain/.well-known/acme-challenge/TOKEN`. Requires port 80 access. Cannot be used for wildcards.

**DNS-01:** Add a TXT record `_acme-challenge.domain` with a key authorization hash. Can validate wildcards (`*.example.com`). Requires DNS API access.

**TLS-ALPN-01:** Present a special self-signed certificate during a TLS handshake with ALPN protocol "acme-tls/1". Good for servers without HTTP.

---

### 4.7 Code Signing

**Authenticode (Windows):**
```
signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256
              /f cert.pfx /p password app.exe
```
Timestamp countersignatures extend validity past certificate expiration.

**Apple Notarization:** macOS Gatekeeper requires code signing + notarization (Apple scans for malware). Notarization ticket is stapled to the binary.

**Sigstore / cosign:** Open-source code signing using ephemeral certificates tied to OIDC identity (GitHub Actions, Google accounts). Keyless signing — private keys are generated in memory and discarded; the certificate is logged in Rekor (transparency log).

```bash
cosign sign --key cosign.key image:tag
cosign verify --key cosign.pub image:tag
```

---

### 4.8 S/MIME

S/MIME (Secure/Multipurpose Internet Mail Extensions) provides email signing and encryption.

**Email signing:** SHA-256 signature over email content, attached as PKCS#7 (CMS) structure. Provides authenticity and non-repudiation.

**Email encryption:** Recipient's public key encrypts a symmetric key; symmetric key encrypts email body. Encrypted with CMS EnvelopedData.

**WKD (Web Key Directory):** OpenPGP key distribution standard. Keys hosted at `https://openpgpkey.domain/.well-known/openpgpkey/domain/hu/[hash of email local part]`. Allows automatic key discovery.

---

## 5. TLS/SSL Security

TLS (Transport Layer Security) is the primary protocol for securing network communication. It provides confidentiality, integrity, and authentication.

### 5.1 TLS 1.3 vs TLS 1.2

#### TLS 1.2 Handshake (simplified)

```
Client → Server: ClientHello (supported ciphers, random, extensions)
Client ← Server: ServerHello (selected cipher, random)
Client ← Server: Certificate
Client ← Server: ServerKeyExchange (DHE/ECDHE params)
Client ← Server: ServerHelloDone
Client → Server: ClientKeyExchange (public key or DH share)
Client → Server: ChangeCipherSpec
Client → Server: Finished (HMAC of handshake)
Client ← Server: ChangeCipherSpec
Client ← Server: Finished
--- Handshake complete: 2 round trips ---
```

#### TLS 1.3 Handshake

```
Client → Server: ClientHello (supported ciphers, key shares for ECDHE groups)
Client ← Server: ServerHello (selected cipher + key share)
Client ← Server: {EncryptedExtensions}  ← encrypted from here on
Client ← Server: {Certificate}
Client ← Server: {CertificateVerify}
Client ← Server: {Finished}
Client → Server: {Finished}
--- Handshake complete: 1 round trip ---
```

**Key improvements in TLS 1.3:**
- 1-RTT handshake (vs 2-RTT in TLS 1.2)
- 0-RTT resumption (with caveats — see below)
- All handshake messages after ServerHello are encrypted
- Removed: RSA key exchange, static DH, non-AEAD ciphers, compression, renegotiation
- Mandatory forward secrecy (ECDHE only)
- Simplified cipher suite list (3 options vs 37+ in TLS 1.2)

#### 0-RTT (Zero Round Trip Time) Resumption Risks

0-RTT allows sending application data in the first flight (before handshake completes) using a Pre-Shared Key (PSK) from a previous session.

**Risks:**
- **Replay attacks:** 0-RTT data can be replayed by a network attacker. Only idempotent requests (GET) should be sent in 0-RTT.
- **No forward secrecy for 0-RTT:** If the PSK is compromised, 0-RTT data is decryptable.
- Single-use tickets mitigate replay but require state on the server.

#### Removed in TLS 1.3

- RC4, DES, 3DES cipher suites
- MD5 and SHA-1 in signatures
- RSA PKCS#1 v1.5 key exchange
- DHE with finite field groups (replaced by ECDHE)
- CBC mode ciphers (BEAST, Lucky13 mitigation)
- Compression (CRIME mitigation)
- Renegotiation (triple handshake attack mitigation)
- Weak export cipher suites

---

### 5.2 Cipher Suite Naming

**TLS 1.2 cipher suite:** `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`

| Component | Meaning |
|-----------|---------|
| TLS | Protocol |
| ECDHE | Key exchange (Elliptic Curve Diffie-Hellman Ephemeral) |
| RSA | Authentication (certificate key type) |
| AES_256_GCM | Bulk cipher (AES-256 in GCM mode) |
| SHA384 | PRF/MAC algorithm |

**TLS 1.3 cipher suite:** `TLS_AES_256_GCM_SHA384`

TLS 1.3 decouples authentication from cipher suites (auth is in the certificate, not the cipher suite):
| Component | Meaning |
|-----------|---------|
| TLS | Protocol |
| AES_256_GCM | AEAD cipher |
| SHA384 | Hash for HKDF |

**TLS 1.3 cipher suites:**
- `TLS_AES_128_GCM_SHA256` (mandatory)
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

---

### 5.3 TLS Attack History

| Attack | Year | CVE | Target | Mechanism |
|--------|------|-----|--------|-----------|
| BEAST | 2011 | CVE-2011-3389 | TLS 1.0 CBC | Predictable IV, chosen-boundary |
| CRIME | 2012 | CVE-2012-4929 | TLS compression | Compression oracle on cookies |
| BREACH | 2013 | - | HTTP compression | Compression oracle |
| POODLE | 2014 | CVE-2014-3566 | SSL 3.0 CBC | Padding oracle via downgrade |
| Logjam | 2015 | CVE-2015-4000 | DHE export | 512-bit DH precomputation |
| FREAK | 2015 | CVE-2015-0204 | RSA export | 512-bit RSA precomputation |
| DROWN | 2016 | CVE-2016-0800 | SSLv2 | Cross-protocol attack on RSA |
| Lucky13 | 2013 | CVE-2013-0169 | CBC-HMAC | Timing attack on MAC-then-Encrypt |
| ROBOT | 2017 | CVE-2017-13099 | RSA PKCS#1 | Bleichenbacher oracle return |
| Raccoon | 2020 | CVE-2020-1968 | DHE | Timing attack on DH shared secret |

---

### 5.4 Certificate Pinning

Certificate pinning restricts which certificates are trusted for a specific connection, beyond the normal CA validation.

#### HTTP Public Key Pinning (HPKP) — Deprecated

HPKP (RFC 7469) allowed servers to specify via HTTP header which public keys to trust:
```
Public-Key-Pins: pin-sha256="base64=="; pin-sha256="backup=="; max-age=2592000
```

**Why it was deprecated:** Multiple sites locked themselves out permanently after key rotation without backup pins. Chrome removed support in 2018.

#### Current Pinning Approaches

**Leaf certificate pin:** Pin the exact certificate. Requires updating pins with every certificate renewal.

**CA/Intermediate pin:** Pin the intermediate or root CA. More flexible but less specific.

**Implementation (Android):**
```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2025-01-01">
            <pin digest="SHA-256">base64EncodedHash==</pin>
            <pin digest="SHA-256">backupHash==</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

---

### 5.5 Perfect Forward Secrecy (PFS)

PFS ensures that session keys are not compromised even if the server's long-term private key is later exposed.

**Without PFS (RSA key exchange):**
- Client encrypts pre-master secret with server's RSA public key
- If server's RSA private key is compromised later, all past sessions can be decrypted

**With PFS (ECDHE):**
- Client and server generate ephemeral ECDH key pairs for each session
- Ephemeral keys are discarded after the session
- Compromise of long-term key does not reveal past sessions

#### Session Resumption

**Session IDs (TLS 1.2):** Server stores session state keyed by ID. Stateful, limits scalability.

**Session Tickets (TLS 1.2):** Server encrypts session state with a ticket key and sends to client. Stateless but ticket keys must be rotated regularly (STEK rotation). If ticket keys are compromised, past sessions using those tickets can be decrypted (breaks PFS!).

**PSK (TLS 1.3):** Session tickets encrypted with per-ticket keys. Single-use to prevent replay.

---

### 5.6 mTLS (Mutual TLS)

Standard TLS authenticates only the server. mTLS adds client certificate authentication.

```
Client → Server: ClientHello
Client ← Server: ServerHello + Certificate + CertificateRequest
Client → Server: Certificate (client cert) + ClientKeyExchange + CertificateVerify
```

**Enterprise use cases:**
- Service-to-service authentication (zero-trust microservices)
- VPN client authentication
- API authentication (replacing API keys)

**Deployment challenges:**
- Certificate lifecycle management at scale (SPIFFE/SPIRE automates this)
- Client certificate distribution and revocation
- Load balancer certificate forwarding (X-Client-Cert header)

---

### 5.7 TLS Configuration Hardening

#### Mozilla SSL Configuration (Modern)

For services not requiring legacy client support:
```nginx
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_prefer_server_ciphers off;
```

#### Mozilla SSL Configuration (Intermediate)

Balances security and compatibility:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
            ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

**Additional headers:**
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

---

### 5.8 TLS Fingerprinting

TLS fingerprinting identifies client implementations by their TLS ClientHello characteristics.

**JA3 (TLS Client Fingerprint):**
MD5 hash of: `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`

**JA3S (TLS Server Fingerprint):**
MD5 hash of server's ServerHello: `TLSVersion,Cipher,Extensions`

**JARM (Active Server Fingerprint):**
Sends 10 specially crafted ClientHello packets with different parameters, hashes the server's responses. Identifies server implementations (TLS libraries, versions, configs).

**Applications:**
- Malware C2 detection (malware has distinctive JA3 signatures)
- Bot detection (automated crawlers have consistent fingerprints)
- Asset inventory (identify TLS library versions across infrastructure)

---

## 6. Random Number Generation

Cryptographic security depends critically on unpredictable random numbers. Weak RNG is a frequent source of cryptographic vulnerabilities.

### 6.1 RNG Types

**True RNG (TRNG):** Uses physical entropy sources (radioactive decay, thermal noise, photon timing). Non-deterministic. Used to seed CSPRNGs.

**PRNG (Pseudo-Random Number Generator):** Deterministic algorithm producing a sequence from an initial seed. Fast but predictable if seed is known. Examples: MT19937 (Mersenne Twister), LCG. Not suitable for cryptography.

**CSPRNG (Cryptographically Secure PRNG):** PRNG with properties required for cryptography:
1. Statistical randomness (passes all statistical tests)
2. Forward secrecy: knowledge of current state doesn't reveal past output
3. Backward secrecy: knowledge of current state doesn't predict future output (if reseeded)

---

### 6.2 Linux RNG

#### /dev/urandom

Non-blocking CSPRNG. Suitable for all cryptographic use cases. Output may not have been seeded with sufficient entropy immediately after boot (early boot issue, fixed in Linux 5.6+ with getrandom() blocking on first call until seeded).

#### /dev/random

Historically blocked when estimated entropy ran low. This behavior was based on flawed entropy estimation. In Linux 5.6+, /dev/random behavior is identical to /dev/urandom (no blocking after initial seeding).

**Recommendation:** Use `getrandom()` syscall or `/dev/urandom`. The historical advice to use `/dev/random` was incorrect.

#### getrandom() Syscall

```c
#include <sys/random.h>
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
// flags=0: blocks until seeded, then non-blocking
// flags=GRND_NONBLOCK: returns EAGAIN if not seeded
// flags=GRND_RANDOM: uses /dev/random pool (legacy, rarely needed)
```

---

### 6.3 Entropy Sources

**Hardware entropy:**
- **RDRAND (Intel/AMD):** CPU instruction returning hardware random numbers from on-chip TRNG. Fast (GB/s). Used to seed the OS CSPRNG.
- **RDSEED:** Returns raw entropy from hardware source (lower throughput, higher quality)
- **ARM TrngRng:** ARMv8.5-A TRNG instruction

**Environmental entropy:**
- Disk I/O timing
- Network packet timing
- Mouse/keyboard event timing
- Interrupt timing
- CPU performance counter variations

**Virtualization concern:** VMs have reduced entropy sources. Cloud instances using snapshots may share entropy state. Use `virtio-rng` (VM-to-host entropy bridge) in virtualized environments.

---

### 6.4 Dual_EC_DRBG Backdoor

Dual_EC_DRBG (Dual Elliptic Curve Deterministic Random Bit Generator) was standardized by NIST in SP 800-90A (2006) with suspected NSA involvement.

**The backdoor mechanism:**
The algorithm uses two elliptic curve points P and Q. If Q = dP for some secret d (the "backdoor key"), an observer watching 32 bytes of output can predict all future output:

```
Internal state s_i → r_i = (s_i * P).x → output 30 bytes of (s_i * Q).x
Next state: s_{i+1} = (r_i * P).x
With backdoor d: s_{i+1} = d * r_i * P = (s_i * P).x ... recoverable
```

**Timeline:**
- 2007: Cryptographers Shumow and Ferguson publicly identified the potential backdoor
- 2013: Snowden documents confirmed NSA paid RSA Security $10M to make Dual_EC the default in BSAFE library
- 2013: NIST withdrew Dual_EC_DRBG from SP 800-90A

**Lesson:** Do not use random number generators with unexplained constants. Prefer algorithms with justified parameter choices (ChaCha20, Curve25519).

---

### 6.5 Common PRNG Misuse

**Seeding with time:**
```python
# WRONG - time has only ~1 second resolution = very few possible seeds
import random, time
random.seed(int(time.time()))
session_token = random.randint(0, 2**32)  # Predictable!
```

**Using language math.random() / rand():**
```javascript
// WRONG - Math.random() is not cryptographically secure
const token = Math.random().toString(36).substring(2);

// CORRECT
const token = crypto.randomUUID();
```

**Short seeds:**
```python
# WRONG - 32-bit seed has only 2^32 possible states
random.seed(os.getpid())  # PID is often predictable (max ~32768)
```

**Predictable seed from observable state:**
Real-world examples: early SSL session tokens derived from process info, PHP mt_rand() seeded with time (widely exploited 2009-2012).

---

### 6.6 Cryptographic Random in Languages

| Language | Secure Function | Notes |
|----------|-----------------|-------|
| Python | `secrets.token_bytes(n)` | Use `secrets` module, not `random` |
| Python | `os.urandom(n)` | Lower-level, also secure |
| Java | `new SecureRandom()` | Avoid `Random` class |
| Java | `SecureRandom.getInstanceStrong()` | Blocks until high-entropy available |
| JavaScript | `crypto.getRandomValues()` | Browser and Node.js |
| Go | `crypto/rand.Read()` | Not `math/rand` |
| C | `getrandom()` / `RAND_bytes()` | Or read /dev/urandom |
| Rust | `rand::rngs::OsRng` | From `rand` crate |
| PHP | `random_bytes(n)` | Not `rand()` or `mt_rand()` |

```python
import secrets
# Secure token
token = secrets.token_hex(32)  # 32 bytes = 64 hex chars
# Secure random integer
n = secrets.randbelow(100)     # 0 to 99
# Secure choice
choice = secrets.choice(['a', 'b', 'c'])
```

```java
import java.security.SecureRandom;
SecureRandom sr = new SecureRandom();
byte[] key = new byte[32];
sr.nextBytes(key);
```

---

## 7. Cryptographic Attacks

### 7.1 Birthday Attacks

The birthday paradox states that in a group of 23 people, there's a >50% chance two share a birthday. Applied to cryptography:

For a hash function with n-bit output, after ~2^(n/2) random inputs, a collision is expected with ~50% probability.

**Collision probability formula:**
```
P(collision) ≈ 1 - e^(-k²/2n)
```
Where k = number of messages, n = number of possible hash values (2^bits)

**Impact on hash function security:**
- MD5 (128-bit): Collision after ~2^64 operations (broken much earlier in practice)
- SHA-1 (160-bit): Collision after ~2^80 operations (broken in 2017 at ~2^63)
- SHA-256 (256-bit): Collision after ~2^128 operations (secure)

**Birthday bound for block ciphers:** With 64-bit block (3DES, Blowfish), collisions occur after ~2^32 = 4 billion blocks. SWEET32 exploited this.

---

### 7.2 Brute Force vs. Rainbow Tables

**Brute force:** Exhaustively try all possible inputs. Time complexity: O(N) for N possibilities.

**Rainbow tables:** Precomputed time-memory trade-off. Hash chains stored with endpoints:
```
p0 → h0 → p1 → h1 → p2 → h2 → ... → hk  (chain)
Store: (p0, hk)
```

To crack hash h:
1. Apply reduction function repeatedly to h, checking if any intermediate equals a stored endpoint
2. If match found, regenerate chain from stored start to find the plaintext

**Size:** Rainbow tables for all 8-character passwords (all printable): ~200 GB

**Defeating rainbow tables:** Salt! Add a unique per-password salt to the hash input:
```
stored = salt || hash(salt || password)
```

A rainbow table must be recomputed for each unique salt, making precomputation infeasible.

**Why salting defeats rainbow tables but not brute force:** Salting adds no significant cost to individual password attempts. Bcrypt/Argon2 add computational cost per attempt, making brute force slow.

---

### 7.3 Side-Channel Attacks

Side-channel attacks exploit information leaked by the physical implementation, not algorithm weaknesses.

#### Timing Attacks

Execution time varies based on secret data.

**Classic example — RSA square-and-multiply:**
```
For each bit b in exponent d:
  state = state^2 mod n  (always)
  if b == 1:
    state = state * c mod n  (only for 1-bits)
```

Measuring timing across many decryptions allows bit-by-bit exponent recovery.

**String comparison timing:**
```python
# Vulnerable - returns as soon as mismatch found
if provided_mac == expected_mac:

# Secure - always compares all bytes
import hmac
if hmac.compare_digest(provided_mac, expected_mac):
```

#### Power Analysis

**SPA (Simple Power Analysis):** Single trace analysis. Different operations (multiply vs. square) have different power signatures.

**DPA (Differential Power Analysis):** Statistical analysis of many power traces to extract key bits. Used to break hardware implementations of AES, DES.

**Countermeasures:** Masking (XOR state with random values before operations, remove mask after), shuffling (randomize operation order), hardware countermeasures.

#### Cache Attacks

**Flush+Reload:** Attacker and victim share memory (VMs on same host):
1. Attacker flushes cache line of AES S-box entry
2. Victim encrypts something
3. Attacker measures reload time — fast = victim accessed that cache line = reveals key bits

**Spectre / Meltdown:** Microarchitectural timing attacks exploiting speculative execution. Spectre variant 1 can be used for S-box leakage at the microarchitectural level.

**Mitigations:** Constant-time implementations (avoid secret-dependent memory accesses), process isolation, AESNI instruction (avoids S-box table lookups entirely).

---

### 7.4 Fault Injection Attacks

Physical attacks that induce computation errors to extract secrets.

**Voltage glitching:** Brief voltage supply dip causes CPU to skip instructions or corrupt registers. Can bypass secure boot checks or induce CRT faults in RSA.

**Clock glitching:** Inject extra clock pulse during critical computation.

**Laser fault injection:** Focused laser hits die to flip individual bits. Used in lab settings to break smart card security.

**EM fault injection:** Electromagnetic pulse induces faults without physical contact.

**Bellcore attack on RSA-CRT:** A single fault during CRT computation leaks the factorization of n:
```
Faulty signature f': gcd(f' - correct, n) = p  (one prime factor)
```

**Countermeasures:**
- Verify signature before returning (RSA)
- Environmental sensors (detect voltage/temperature anomalies)
- Redundant computation with comparison
- Physical security (tamper detection, potting)

---

### 7.5 Quantum Threats

**Shor's Algorithm (1994):** Polynomial-time quantum algorithm for:
- Integer factorization → breaks RSA
- Discrete logarithm → breaks DH, DSA, ECDH, ECDSA
- Runs in O(n^3) on a quantum computer with ~4000 logical qubits for 2048-bit RSA

**Impact on asymmetric cryptography:**
- RSA-2048: ~4000 logical qubits → completely broken
- ECDH/ECDSA P-256: ~2000 logical qubits → completely broken
- All current public-key cryptography is broken by sufficiently large quantum computers

**Grover's Algorithm (1996):** Quantum search algorithm providing quadratic speedup for unstructured search.

**Impact on symmetric cryptography:**
- AES-128: Security reduced to 64-bit (insecure) → use AES-256
- AES-256: Security reduced to 128-bit (acceptable)
- SHA-256: Collision resistance reduced from 128-bit to 85-bit (still acceptable)
- SHA-3: Similar impact to SHA-2

**Current state (2024):** Best quantum computers have ~1000-2000 noisy physical qubits. Cryptographically relevant attacks require millions of logical qubits (after error correction). Timeline estimates vary: 10-30 years for relevant quantum computers.

---

### 7.6 Post-Quantum Cryptography

NIST standardized PQC algorithms in 2024 (FIPS 203, 204, 205).

#### ML-KEM / CRYSTALS-Kyber (FIPS 203)

Key Encapsulation Mechanism based on Module Learning With Errors (MLWE) problem.

```
Parameter sets:
- ML-KEM-512: NIST security level 1 (~AES-128 classical, 128-bit quantum)
- ML-KEM-768: NIST security level 3 (~AES-192)  [recommended]
- ML-KEM-1024: NIST security level 5 (~AES-256)
```

Key/ciphertext sizes (ML-KEM-768): public key 1184 bytes, ciphertext 1088 bytes.

#### ML-DSA / CRYSTALS-Dilithium (FIPS 204)

Digital signature based on Module Learning With Errors.

```
Parameter sets:
- ML-DSA-44: security level 2
- ML-DSA-65: security level 3  [recommended]
- ML-DSA-87: security level 5
```

Signature sizes: 2420-4595 bytes (larger than ECC's 64 bytes).

#### SLH-DSA / SPHINCS+ (FIPS 205)

Hash-based signature scheme. Security relies only on hash function security (conservative choice).

- Larger signatures (~8-50 KB depending on parameter set)
- Slower signing than ML-DSA
- Alternative for environments where lattice assumptions are doubted

#### FALCON (FN-DSA, draft FIPS 206)

NTRU lattice-based signature. Compact signatures (~700 bytes) but complex implementation.

#### Hybrid Approaches

Combine classical (ECDH) and post-quantum (ML-KEM) in key exchange:
```
combined_secret = ECDH_secret || ML-KEM_secret
session_key = KDF(combined_secret)
```

Used in: TLS 1.3 hybrid key exchange (X25519+ML-KEM-768), Signal Protocol, Google Chrome.

---

### 7.7 Harvest Now, Decrypt Later (HNDL)

Nation-state adversaries may be recording encrypted traffic today to decrypt once quantum computers become available.

**Timeline concern:** Data with 10+ year sensitivity (state secrets, long-term contracts, medical records) is at risk if encrypted with classical algorithms today.

**Affected algorithms:** RSA, ECDH (key exchange) — compromise of past sessions is possible. AES-256 is quantum-resistant (symmetric).

**Mitigation:**
- Deploy post-quantum key exchange (ML-KEM) NOW for key agreement
- Classical symmetric ciphers (AES-256) remain safe
- Certificate/signature algorithms (RSA, ECDSA) are less urgent (forward secrecy mitigates)

**Timeline:**
- 2022: NIST announced PQC finalists
- 2024: FIPS 203/204/205 published
- 2025+: TLS, SSH, and PKI ecosystems adopt PQC

---

## 8. Applied Cryptography

### 8.1 JWT Security

JSON Web Tokens (RFC 7519) consist of three Base64URL-encoded parts: Header.Payload.Signature.

#### Algorithm:None Attack

If a JWT library accepts `"alg":"none"` (unsigned token), an attacker can:
```json
{"alg":"none","typ":"JWT"}  →  {"sub":"admin","role":"admin"}  →  (no signature)
```

Produce an admin token without knowing any secret. Many early libraries were vulnerable.

**Mitigation:** Always explicitly specify allowed algorithms in JWT verification. Never accept "none".

#### RSA to HS256 Confusion Attack

If a server uses RSA public key verification and the library accepts the public key as an HMAC secret:
```
Normal: Header={"alg":"RS256"} → verify with RSA public key
Attack: Header={"alg":"HS256"} → verify with HMAC-SHA256(public key)
```

The public key is known to the attacker. They sign a forged token with HMAC-SHA256 using the RSA public key, and the library verifies it successfully.

**Mitigation:** Explicitly specify the algorithm, not just the key. Libraries must not allow alg confusion.

#### Weak JWT Secrets

HS256 JWTs signed with weak secrets can be brute-forced:
```bash
# hashcat can crack weak JWT secrets
hashcat -a 0 -m 16500 token.jwt wordlist.txt
```

**Mitigation:** Use minimum 256-bit random secrets for HS256. Or prefer RS256/ES256 with proper key management.

---

### 8.2 OAuth/OIDC Cryptographic Components

**JWK (JSON Web Key):** JSON representation of cryptographic keys.
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "base64url...",
  "y": "base64url...",
  "kid": "key-id-1"
}
```

**JWE (JSON Web Encryption):** Encrypted JWT. Uses hybrid encryption: randomly generated CEK (Content Encryption Key) encrypted with recipient's public key, payload encrypted with CEK using AES-GCM or ChaCha20-Poly1305.

**PKCE (Proof Key for Code Exchange):** For public OAuth clients (mobile apps, SPAs):
```
code_verifier = random 32+ byte string
code_challenge = BASE64URL(SHA256(code_verifier))
```
Sent with authorization request; verifier sent with token request. Prevents authorization code interception attacks.

---

### 8.3 Disk Encryption

**LUKS (Linux Unified Key Setup):**
- Header stores encrypted master key (MK) slots (up to 8 passphrases/keyfiles)
- Each slot: PBKDF2/Argon2 derivation → AES key → encrypted MK
- Payload: AES-XTS encrypted data (XTS mode provides sector-level encryption)
- LUKS2: Argon2id for key derivation, integrity support (dm-integrity)

```bash
# Create LUKS volume
cryptsetup luksFormat --type luks2 /dev/sdX
# Open
cryptsetup luksOpen /dev/sdX encrypted_disk
# Show info
cryptsetup luksDump /dev/sdX
```

**BitLocker:**
- Windows disk encryption using AES-XTS 256-bit
- Key stored in TPM (with optional PIN/USB key)
- Recovery key: 48-digit number (backed up to AD or Microsoft account)
- VMK (Volume Master Key) → FVEK (Full Volume Encryption Key)

**VeraCrypt:**
- Open-source, TrueCrypt successor
- Hidden volumes (plausible deniability)
- Cascade encryption: AES-Twofish-Serpent
- PBKDF2-SHA512 with high iteration count

---

### 8.4 File Encryption

**age (Actually Good Encryption):**
Simple, modern file encryption tool by Filippo Valsorda.
```bash
# Encrypt to recipient's public key
age -r age1ql3z7hjy54... plaintext.txt > encrypted.age
# Decrypt
age -d -i key.txt encrypted.age > plaintext.txt
# Password encryption
age -p plaintext.txt > encrypted.age
```
Uses X25519 key exchange + ChaCha20-Poly1305 encryption.

**GPG Best Practices:**
```bash
# Generate key (Ed25519 + X25519)
gpg --full-gen-key  # choose Ed25519

# Encrypt + sign
gpg --encrypt --sign --armor -r recipient@email.com file.txt

# Use subkeys, not master key, for daily operations
# Back up master key offline
# Set key expiration (1-2 years)
# Use keyserver or WKD for key distribution
```

---

### 8.5 Signal Protocol

The Signal Protocol provides end-to-end encrypted messaging with strong forward secrecy and break-in recovery.

#### X3DH (Extended Triple Diffie-Hellman) Key Agreement

Initial session establishment using prekeys:

```
Bob's published keys:
  IK_B: Identity key (Ed25519)
  SPK_B: Signed prekey (X25519, rotated weekly)
  OPK_B: One-time prekey (X25519, consumed once)

Alice computes 4 DH values:
  DH1 = DH(IK_A, SPK_B)  (authenticity)
  DH2 = DH(EK_A, IK_B)   (authenticity)
  DH3 = DH(EK_A, SPK_B)  (forward secrecy)
  DH4 = DH(EK_A, OPK_B)  (one-time forward secrecy)

Master secret = KDF(DH1 || DH2 || DH3 || DH4)
```

#### Double Ratchet Algorithm

Combines two ratchets for forward secrecy (past messages) and break-in recovery (future messages):

**Diffie-Hellman Ratchet:** Advances when new DH public keys are exchanged (each message roundtrip).

**Symmetric-Key Ratchet (KDF chains):** Derives message keys from chain keys:
```
chain_key, message_key = KDF_CK(chain_key)
```

Forward secrecy: Message keys are deleted after use. Past messages cannot be decrypted even if current state is compromised.

Break-in recovery: New DH values are exchanged frequently, providing healing from compromises.

---

### 8.6 Homomorphic Encryption

Homomorphic encryption (HE) allows computation on encrypted data without decryption.

**Types:**
- **PHE (Partially HE):** One operation type (e.g., RSA for multiplication, Paillier for addition)
- **SHE (Somewhat HE):** Both addition and multiplication, but limited circuit depth
- **FHE (Fully HE):** Arbitrary computations. Bootstrapping re-encrypts ciphertext to reset noise.

**Popular FHE schemes:**
- **BFV/BGV:** Integer arithmetic, batch operations via SIMD (Microsoft SEAL, HElib)
- **CKKS:** Approximate floating-point arithmetic, ML workloads (OpenFHE)
- **TFHE:** Fast bootstrapping (~13ms), bit-by-bit operations

**Current performance:** 100x - 10000x slower than plaintext computation. Improving rapidly.

**Use cases:**
- Privacy-preserving ML inference (model on server, data remains encrypted)
- Secure multiparty computation
- Private information retrieval (query database without revealing query)
- Encrypted database queries

---

### 8.7 Threshold Cryptography

#### Shamir's Secret Sharing

Split a secret S into n shares such that any k shares can reconstruct S, but k-1 shares reveal nothing.

**Construction:** Choose a random polynomial of degree k-1:
```
f(x) = S + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}  (mod prime p)
Share_i = (i, f(i))
```

Reconstruct with k shares using Lagrange interpolation:
```
S = f(0) = sum over i of (y_i * product over j≠i of (x_j / (x_j - x_i)))
```

**Applications:** Master key splitting, HSM quorum, disaster recovery keys.

#### Multi-Party Computation (MPC)

Allows multiple parties to jointly compute a function over their private inputs without revealing those inputs.

**Applications:**
- Threshold signatures (k-of-n parties must cooperate to sign)
- Private set intersection (find common elements without revealing sets)
- Secure auctions (winner determination without revealing bids)
- Distributed key generation (no single party has the full key)

**Protocols:** Garbled circuits (Yao), secret sharing-based MPC (SPDZ, MASCOT), homomorphic encryption-based.

---

## 9. Cryptographic Libraries and Implementation

### 9.1 OpenSSL

Most widely deployed cryptographic library. Used in Apache, Nginx, many applications.

```bash
# Generate RSA private key
openssl genrsa -out key.pem 4096

# Generate RSA private key with AES-256 encryption
openssl genrsa -aes256 -out key.pem 4096

# Generate EC private key (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out ec-key.pem

# Generate Ed25519 private key
openssl genpkey -algorithm ed25519 -out ed-key.pem

# Create Certificate Signing Request
openssl req -new -key key.pem -out cert.csr \
  -subj "/C=US/O=Example/CN=example.com"

# Self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=example.com"

# View certificate details
openssl x509 -in cert.pem -text -noout

# View certificate subject and dates only
openssl x509 -in cert.pem -noout -subject -dates -fingerprint

# Verify certificate chain
openssl verify -CAfile ca-bundle.crt cert.pem

# Test TLS connection (TLS 1.3)
openssl s_client -connect example.com:443 -tls1_3

# Test TLS with SNI
openssl s_client -connect example.com:443 -servername example.com

# Check OCSP status
openssl s_client -connect example.com:443 -status 2>/dev/null | grep "OCSP"

# Create PKCS#12 bundle
openssl pkcs12 -export -out bundle.p12 -inkey key.pem -in cert.pem -certfile chain.pem

# Encrypt file (using AES-256-CBC)
openssl enc -aes-256-cbc -pbkdf2 -in plaintext.txt -out encrypted.bin

# Decrypt file
openssl enc -d -aes-256-cbc -pbkdf2 -in encrypted.bin -out plaintext.txt

# Compute SHA-256 hash
openssl dgst -sha256 file.txt

# Sign file
openssl dgst -sha256 -sign key.pem -out sig.bin file.txt

# Verify signature
openssl dgst -sha256 -verify pub.pem -signature sig.bin file.txt

# Generate random bytes (hex)
openssl rand -hex 32

# Check supported ciphers
openssl ciphers -v 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5'
```

---

### 9.2 libsodium

High-level, easy-to-use cryptographic library. Designed to prevent common mistakes.

```c
#include <sodium.h>

// Key generation
unsigned char pk[crypto_box_PUBLICKEYBYTES];
unsigned char sk[crypto_box_SECRETKEYBYTES];
crypto_box_keypair(pk, sk);

// Authenticated encryption (X25519 + XSalsa20 + Poly1305)
unsigned char nonce[crypto_box_NONCEBYTES];
randombytes_buf(nonce, sizeof nonce);
crypto_box_easy(ciphertext, message, msg_len, nonce, recipient_pk, sender_sk);

// Decryption
crypto_box_open_easy(decrypted, ciphertext, cipher_len, nonce, sender_pk, recipient_sk);

// Secret key encryption (XSalsa20-Poly1305)
unsigned char key[crypto_secretbox_KEYBYTES];
crypto_secretbox_easy(ciphertext, message, msg_len, nonce, key);

// Password hashing (Argon2id)
char hash[crypto_pwhash_STRBYTES];
crypto_pwhash_str(hash, password, pwd_len,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE);

// Verify password
if (crypto_pwhash_str_verify(hash, password, pwd_len) == 0) {
    // Correct password
}
```

**NaCl compatibility:** libsodium is based on NaCl (Networking and Cryptography library) by Bernstein. Same algorithms, compatible API.

**Key design principle:** The default choices are always secure. You can't accidentally choose a broken algorithm.

---

### 9.3 Other Libraries

**Bouncy Castle (Java/C#):**
- Comprehensive, low-level crypto library
- Full X.509 and CMS/PKCS support
- JCE provider for Java applications
- Used in Android, many enterprise applications

**PyCryptodome (Python):**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # AES-256
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

**cryptography.io (Python):**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
pt = aesgcm.decrypt(nonce, ct, aad)
```

Preferred over PyCryptodome for new Python code (hazmat layer + high-level recipes).

---

### 9.4 Common Implementation Mistakes

| Mistake | Example | Consequence | Fix |
|---------|---------|-------------|-----|
| Null/zero IV | `iv = b'\x00' * 16` | Deterministic output, breaks GCM | `os.urandom(12)` for GCM |
| ECB mode | `AES.new(key, AES.MODE_ECB)` | Pattern leakage (penguin problem) | Use GCM or CBC with IV |
| MD5 for passwords | `hashlib.md5(password)` | Crackable in seconds | Argon2id, bcrypt, scrypt |
| No MAC | Encrypt-only with CBC | Padding oracle, bit-flipping | Use AEAD (GCM) |
| Hardcoded key | `KEY = b"mysecretkey12345"` | Trivially extracted | Key management system, env vars |
| Non-random nonce | `nonce = counter` | Nonce reuse in GCM → catastrophic | Cryptographic random per message |
| Weak KDF | `key = SHA256(password)` | Fast brute-force | Argon2id with high cost |
| PRNG for keys | `random.randbytes(32)` | Predictable keys | `secrets.token_bytes(32)` |
| Not checking return values | Ignoring `verify()` errors | Silent authentication bypass | Always check auth results |
| Rolling your own crypto | Custom cipher/protocol | Almost certainly broken | Use established libraries |

---

## 10. Compliance and Standards

### 10.1 FIPS 140-2/3

Federal Information Processing Standard 140 defines security requirements for cryptographic modules used by US federal agencies.

#### Security Levels

| Level | Description |
|-------|-------------|
| 1 | Basic security requirements; no physical security |
| 2 | Tamper-evident physical security; role-based authentication |
| 3 | Tamper-resistant; identity-based authentication; private key zeroization |
| 4 | Tamper-active; complete envelope protection; environmental failure protection |

#### FIPS 140-3 (Current Standard)

FIPS 140-3 (2019) is based on ISO/IEC 19790 and ISO/IEC 24759.

**FIPS 140-3 Approved Algorithms (selected):**

| Category | Approved Algorithms |
|----------|---------------------|
| Symmetric encryption | AES (128/192/256-bit) |
| Asymmetric encryption | RSA (2048+), ECDH (P-256, P-384, P-521) |
| Digital signatures | RSA (2048+), ECDSA (P-256, P-384, P-521), EdDSA (Ed25519, Ed448) |
| Hash functions | SHA-1 (limited), SHA-2, SHA-3 |
| MACs | HMAC, CMAC, GMAC |
| KDFs | PBKDF2, HKDF, SP 800-108 KDF, SP 800-132 |
| RNGs | DRBG (CTR, Hash, HMAC based) |

**Not approved:** AES-GCM-SIV (no FIPS validation as of 2024), ChaCha20-Poly1305, Argon2id, Blake2, Curve25519 (though Ed25519 is now approved in FIPS 186-5).

---

### 10.2 NIST SP 800-57: Key Management

SP 800-57 Part 1 Rev 5 (2020) provides key management recommendations.

#### Key Length Recommendations (comparable security)

| Security Strength (bits) | Symmetric Key | RSA/DH | ECC |
|--------------------------|---------------|--------|-----|
| 80 | TDEA (2-key) | 1024 | 160-223 |
| 112 | TDEA (3-key) | 2048 | 224-255 |
| 128 | AES-128 | 3072 | 256-383 |
| 192 | AES-192 | 7680 | 384-511 |
| 256 | AES-256 | 15360 | 512+ |

#### Key Types

- **KEK (Key Encryption Key):** Encrypts other keys
- **DEK (Data Encryption Key):** Encrypts data
- **Private signature key:** RSA/EC signing key
- **Public key certificate:** Binding of public key to identity
- **Symmetric authentication key:** HMAC key
- **RNG seed:** Input to DRBG

#### Key Usage Periods

NIST recommends limiting key usage:
- Originator usage period: How long a key is used to protect data
- Recipient usage period: How long protected data can be decrypted/verified

---

### 10.3 NIST SP 800-131A: Algorithm Transitions

Rev 2 (2019) defines algorithm transition requirements.

**Deprecated (acceptable through 2023):**
- 2TDEA (2-key 3DES): Encryption limited to 2^20 blocks
- SHA-1 for digital signatures: Only for verification of legacy data

**Disallowed (after 2023):**
- 1-key TDEA (single DES)
- 112-bit RSA (< 2048-bit)
- SHA-1 for new signatures

**Acceptable through 2030:**
- RSA-2048 with SHA-256
- ECDSA P-256 with SHA-256
- ECDH P-256

**Recommended for post-2030:**
- RSA-3072 or larger
- ECDSA P-384 or larger
- Add post-quantum algorithms

---

### 10.4 CNSA 2.0 (Commercial National Security Algorithm Suite)

Published by NSA (September 2022). Requirements for NSS (National Security Systems).

**CNSA 2.0 Timeline:**

| System Type | Transition Start | Exclusively PQC |
|-------------|-----------------|-----------------|
| Software and firmware signing | 2025 | 2030 |
| Web browsers and servers | 2025 | 2033 |
| Operating systems | 2026 | 2033 |
| Network equipment | 2026 | 2030 |
| Custom applications | 2026 | 2033 |

**CNSA 2.0 Required Algorithms:**

| Use | Algorithm |
|-----|-----------|
| Key exchange | ML-KEM-1024 |
| Digital signatures | ML-DSA-87 or SLH-DSA (256 security level) |
| Hashing | SHA-384 / SHA-512 |
| Symmetric encryption | AES-256 |
| Key agreement (classical, transitional) | ECDH P-384 |
| Signatures (classical, transitional) | ECDSA P-384 |

---

### 10.5 PCI DSS Cryptographic Requirements

PCI DSS v4.0 (2022) includes specific cryptographic requirements.

**Requirement 3: Protect stored account data**
- Render PAN (Primary Account Number) unreadable using strong cryptography
- Accepted methods: one-way hash, truncation, index token, strong encryption
- Disk-level or volume-level encryption: only acceptable with additional access controls
- Key management: separate key from encrypted data, protect keys with key-encrypting keys, split knowledge/dual control for key custodians

**Requirement 4: Protect cardholder data with strong cryptography during transmission**
- Use strong cryptography (TLS 1.2 minimum, TLS 1.3 preferred) for cardholder data in transit
- Disable SSL/early TLS entirely
- PAN unreadable in transit
- TLS for all public-facing web applications

**PCI-defined "strong cryptography":**
Industry-proven, accepted algorithms with key lengths meeting minimum lengths per algorithm type. Must not be breakable in a commercially reasonable timeframe. Reference: NIST, ISO standards.

**Key management requirements (3.7):**
- Key generation: secure location, approved algorithms
- Key distribution: secure, documented process
- Key storage: encrypted, minimum access
- Key retirement/replacement: defined intervals, when compromised
- Key destruction: documented, renders key unrecoverable
- Key custodian responsibility: formal acknowledgment

---

### 10.6 Common Criteria (CC)

International standard (ISO/IEC 15408) for evaluating security properties of IT products.

**Evaluation Assurance Levels (EAL):**

| Level | Description | Typical Use |
|-------|-------------|-------------|
| EAL1 | Functionally tested | Low assurance |
| EAL2 | Structurally tested | Simple products |
| EAL3 | Methodically tested | Standard commercial |
| EAL4+ | Methodically designed, tested, reviewed | Government, HSMs |
| EAL5 | Semi-formally designed | High security |
| EAL6 | Semi-formally verified | Very high security |
| EAL7 | Formally verified | Military, specialized |

**Protection Profiles for crypto:**
- EN 419 211: Security requirements for trustworthy systems
- FIPS 140 evaluation is separate (CMVP program), often combined with CC evaluation for HSMs

**HSM certifications:** Hardware Security Modules (HSMs) used for key storage typically hold both FIPS 140-3 Level 3+ and CC EAL4+ certifications. Examples: Thales Luna HSM, Utimaco, AWS CloudHSM.

---

## Quick Reference: Algorithm Recommendations (2024)

### Symmetric Encryption
- **Use:** AES-256-GCM or ChaCha20-Poly1305
- **Avoid:** AES-ECB, AES-CBC without authentication, DES, 3DES, RC4

### Asymmetric Encryption
- **Use:** RSA-4096 with OAEP, ECIES with P-256/X25519
- **Avoid:** RSA-1024/2048 PKCS#1 v1.5, raw RSA

### Key Exchange
- **Use:** ECDHE (X25519 preferred, P-256 acceptable), ML-KEM-768 (PQC)
- **Avoid:** RSA key transport, DHE < 2048-bit, static DH

### Digital Signatures
- **Use:** Ed25519, ECDSA P-256, RSA-PSS 4096
- **Avoid:** ECDSA without deterministic nonce, RSA-PKCS1v1.5 signing, DSA

### Hash Functions
- **Use:** SHA-256, SHA-384, SHA-512, SHA-3, BLAKE3
- **Avoid:** MD5, SHA-1 (for new applications)

### Password Hashing
- **Use:** Argon2id (preferred), bcrypt (cost 12+), scrypt
- **Avoid:** Plain SHA, MD5, SHA-256 without KDF, PBKDF2 with < 600,000 iterations

### Random Numbers
- **Use:** OS CSPRNG (`os.urandom`, `crypto.getRandomValues`, `SecureRandom`)
- **Avoid:** `rand()`, `Math.random()`, time-based seeds

### TLS Configuration
- **Use:** TLS 1.3 (TLS 1.2 minimum), ECDHE, AES-256-GCM or ChaCha20-Poly1305
- **Avoid:** SSLv3, TLS 1.0/1.1, RC4, DES, MD5, export ciphers, NULL ciphers

---

*Last updated: 2024. Standards and recommendations evolve — always verify against current NIST, IETF, and vendor guidance.*
