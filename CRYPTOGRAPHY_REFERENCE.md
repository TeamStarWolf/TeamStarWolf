# Cryptography Reference

> **Scope**: Symmetric and asymmetric encryption, hash functions, TLS/SSL, PKI, key management, post-quantum cryptography, and cryptographic attack techniques.
> Mapped to NIST SP 800-57, NIST FIPS 140-3, NIST PQC FIPS 203/204/205, and MITRE ATT&CK credential-access techniques.

---

## Table of Contents

- [Symmetric Encryption](#symmetric-encryption)
- [Asymmetric / Public Key Cryptography](#asymmetric--public-key-cryptography)
- [Hash Functions](#hash-functions)
- [TLS / SSL](#tls--ssl)
- [PKI & Certificates](#pki--certificates)
- [Key Management](#key-management)
- [Cryptographic Attacks Reference](#cryptographic-attacks-reference)
- [Algorithm Selection Cheat Sheet](#algorithm-selection-cheat-sheet)
- [Do-Not-Use List](#do-not-use-list)

---

## Symmetric Encryption

### Block Ciphers

**AES (Advanced Encryption Standard)**

| Key Size | Security Level | Notes |
|---|---|---|
| AES-128 | ~128-bit | Acceptable; sufficient for most use cases |
| AES-192 | ~192-bit | Rarely used; minor performance cost |
| AES-256 | ~256-bit | Preferred for high-value data and post-quantum margin |

- Block size: **128 bits** (16 bytes) for all AES variants
- NIST FIPS 197 standard; hardware acceleration (AES-NI) on modern CPUs

### Modes of Operation

| Mode | Authenticated | Parallelizable | Notes |
|---|---|---|---|
| ECB | No | Yes (enc+dec) | **BROKEN — never use.** Identical plaintext blocks produce identical ciphertext blocks ("penguin diagram" / ECB bitmap attack) |
| CBC | No | Decrypt only | Requires random IV; vulnerable to **padding oracle attacks** (POODLE, BEAST, Lucky13); use Encrypt-then-MAC or switch to AEAD |
| CTR | No | Yes | Turns block cipher into stream cipher; no padding needed; IV/nonce must never repeat |
| GCM | Yes (GHASH) | Yes | **Preferred AEAD mode.** Combines CTR encryption with polynomial MAC; 96-bit nonce, 128-bit tag |
| CCM | Yes | No | AES-CCM used in 802.11i/WPA2 and TLS; limited to 2^23 blocks per key/nonce pair |
| SIV | Yes | Dec only | Nonce-misuse resistant; deterministic; good for key wrapping and DAE |

### AES-256-GCM Requirements

- **Nonce/IV**: 96 bits (12 bytes); **never reuse a nonce under the same key** — nonce reuse destroys confidentiality and authentication
- Nonce generation: use a cryptographically secure RNG; consider deterministic counter with strict tracking for high-volume scenarios
- **Authentication tag**: 128 bits (16 bytes); truncation below 96 bits is non-compliant (NIST SP 800-38D)
- **Additional Authenticated Data (AAD)**: binds ciphertext to context (e.g., version, recipient ID, header); not encrypted but integrity-protected
- Key lifetime: limit plaintext encrypted per key (`2^32` blocks / ~64 GiB under the same key/nonce space before rekeying)

### ChaCha20-Poly1305

- Stream cipher (ChaCha20) combined with Poly1305 MAC — an AEAD construction
- **Advantages over AES-GCM on non-AES-NI hardware**: constant-time software implementation; no timing side-channel risk from table lookups
- Used in TLS 1.3 cipher suite: `TLS_CHACHA20_POLY1305_SHA256`
- 256-bit key; 96-bit nonce; 128-bit authentication tag
- Nonce rules identical to AES-GCM — never reuse

### Stream Ciphers

| Cipher | Status | Notes |
|---|---|---|
| RC4 | **BROKEN — never use** | Biases in keystream; broken in WEP/WPA/TLS; RFC 7465 prohibits RC4 in TLS |
| ChaCha20 | Secure | Use with Poly1305 MAC (ChaCha20-Poly1305 AEAD) |
| Salsa20 | Secure | Predecessor to ChaCha20; less widely adopted |

### Key Size Recommendations (NIST SP 800-57 Part 1)

| Algorithm | Key Size | Security Bits | Valid Through |
|---|---|---|---|
| AES | 128 | 128 | 2030+ |
| AES | 192 | 192 | 2030+ |
| AES | 256 | 256 | 2030+ |
| 3DES (TDEA) | 112 effective | 112 | **Deprecated 2024 (NIST SP 800-131A r2)** |
| DES | 56 | <56 | **Disallowed** |

### Symmetric Attack Types

| Attack | Description | Mitigation |
|---|---|---|
| Brute Force | Exhaustively try all keys | Sufficient key size (≥128-bit) |
| Meet-in-the-Middle | Attacks double encryption (e.g., 2DES) | Use single strong cipher (AES-256) |
| Related-Key | Exploit mathematical relationship between keys | Key schedule independence; avoid manual key derivation |
| Side-Channel — Timing | Measure execution time to infer key bits | Constant-time implementations; AES-NI |
| Side-Channel — Cache | Flush+Reload, Prime+Probe on table-based AES | AES-NI hardware; constant-time code |
| Side-Channel — Power | Measure power consumption (DPA) on embedded devices | Hardware countermeasures; masking |

---

## Asymmetric / Public Key Cryptography

### RSA

**Key Generation**
1. Choose two large random primes `p` and `q`
2. Compute `n = p * q` (modulus)
3. Compute `λ(n) = lcm(p-1, q-1)` (Carmichael's totient)
4. Choose `e = 65537` (standard public exponent; Fermat prime F4)
5. Compute `d ≡ e⁻¹ (mod λ(n))` (private exponent)
6. Public key: `(n, e)` — Private key: `(n, d)`

**Key Size Recommendations**

| RSA Key Size | Security Bits | Recommendation |
|---|---|---|
| 1024-bit | ~80 | **Broken — do not use** |
| 2048-bit | ~112 | **Minimum acceptable** (legacy systems only) |
| 3072-bit | ~128 | **Recommended for new deployments** |
| 4096-bit | ~140 | High-security / long-lived keys |

**Padding Schemes**

| Scheme | Use Case | Status | Notes |
|---|---|---|---|
| PKCS#1 v1.5 Encryption | Encryption | **Vulnerable — avoid** | Bleichenbacher 1998 padding oracle; ROBOT attack 2017 in TLS |
| OAEP (RSAES-OAEP) | Encryption | Secure | Use SHA-256 as hash; PKCS#1 v2.2 |
| PKCS#1 v1.5 Signature | Signatures | Marginally acceptable | Prone to implementation errors; prefer PSS |
| PSS (RSASSA-PSS) | Signatures | **Recommended** | Probabilistic; provably secure; use SHA-256+ |

### Elliptic Curve Cryptography (ECC)

**Curve Comparison**

| Curve | Also Known As | Key Size | Security Bits | Use Case |
|---|---|---|---|---|
| P-256 | secp256r1, prime256v1 | 256-bit | ~128 | TLS, ECDSA, ECDH; most widely deployed |
| P-384 | secp384r1 | 384-bit | ~192 | High-security TLS; NSA Suite B |
| P-521 | secp521r1 | 521-bit | ~260 | Very high security; rare |
| X25519 | Curve25519 (ECDH) | 255-bit | ~128 | **Preferred for ECDH key exchange**; constant-time; TLS 1.3 default |
| X448 | Curve448 (ECDH) | 448-bit | ~224 | High-security ECDH; TLS 1.3 |
| Ed25519 | edwards25519 (EdDSA) | 255-bit | ~128 | **Preferred for signatures**; SSH keys, JWT, code signing |
| Ed448 | edwards448 (EdDSA) | 448-bit | ~224 | High-security signatures |
| secp256k1 | Bitcoin curve | 256-bit | ~128 | Cryptocurrency; avoid in general TLS |

**ECDH Key Exchange**
1. Alice generates ephemeral keypair `(d_A, Q_A)` where `Q_A = d_A * G`
2. Bob generates ephemeral keypair `(d_B, Q_B)` where `Q_B = d_B * G`
3. Alice computes shared secret: `S = d_A * Q_B`
4. Bob computes shared secret: `S = d_B * Q_A`
5. Both arrive at same point `S`; derive key material via KDF (HKDF)

**ECDSA Signing**
- Sign: `(r, s)` where `r = (k*G).x mod n`, `s = k⁻¹(hash + r*d) mod n`
- **Critical**: `k` (signing nonce) must be unique and unpredictable per signature — reuse leaks the private key (Sony PS3 breach, blockchain attacks)
- Prefer deterministic ECDSA (RFC 6979) or use EdDSA (Ed25519) which is inherently deterministic

### Diffie-Hellman (DH / ECDH)

- **Classic DH**: Based on discrete logarithm problem in finite fields; requires 2048-bit minimum group (RFC 3526 Group 14); 3072-bit recommended for new deployments
- **ECDH**: Same concept over elliptic curves; X25519 is the modern standard
- **Ephemeral DH (DHE/ECDHE)**: New key pair per session — provides **forward secrecy** (compromise of long-term key does not decrypt past sessions)
- **Safe prime groups**: Classic DH parameters must use safe primes (`p = 2q + 1`); use RFC 3526 or RFC 7919 named groups rather than custom parameters

### Post-Quantum Cryptography (PQC)

**NIST PQC Standards (2024)**

| Standard | Algorithm | Type | FIPS |
|---|---|---|---|
| ML-KEM | CRYSTALS-Kyber | Key Encapsulation Mechanism (KEM) | FIPS 203 |
| ML-DSA | CRYSTALS-Dilithium | Digital Signature | FIPS 204 |
| SLH-DSA | SPHINCS+ | Digital Signature (stateless hash-based) | FIPS 205 |
| FN-DSA | FALCON | Digital Signature | Draft FIPS 206 |

**Threat Context**
- **Shor's algorithm** (quantum): Breaks RSA and ECC in polynomial time → all current public-key crypto is vulnerable to a sufficiently large quantum computer
- **Grover's algorithm** (quantum): Provides quadratic speedup for brute force → halves effective symmetric key strength (AES-128 → ~64-bit effective; AES-256 → ~128-bit effective)
- **"Harvest now, decrypt later"**: Adversaries collect encrypted traffic today for future quantum decryption — migrate long-lived secrets now

**Migration Timeline**
- **2025**: Begin hybrid classical + PQC deployments; test ML-KEM and ML-DSA in non-critical paths
- **2026–2028**: Replace RSA/ECC key exchange with ML-KEM in TLS and SSH
- **2030**: NIST target for full transition of federal systems; RSA-2048 and P-256 reach end-of-security-life

**Hybrid Key Exchange**: Combine classical ECDH (X25519) with ML-KEM — provides security if either algorithm is not broken; used in TLS 1.3 extensions (RFC 8446 hybrid groups)

---

## Hash Functions

### Algorithm Comparison

| Algorithm | Output Size | Speed | Collision Resistance | Pre-image Resistance | Status / Use Case |
|---|---|---|---|---|---|
| MD5 | 128-bit | Very fast | **Broken (2004)** | Weakened | **Do not use** for security; only legacy checksums |
| SHA-1 | 160-bit | Fast | **Broken (SHAttered 2017)** | Weakened | **Do not use**; deprecated in TLS, certificates, Git |
| SHA-256 | 256-bit | Moderate | 128-bit security | 256-bit security | General purpose; TLS, certificates, HMAC |
| SHA-384 | 384-bit | Moderate | 192-bit security | 384-bit security | High-security signatures; NSA Suite B |
| SHA-512 | 512-bit | Fast on 64-bit | 256-bit security | 512-bit security | File integrity; HMAC-SHA512 |
| SHA-3/Keccak-256 | 256-bit | Slower | 128-bit security | 256-bit security | Alternative to SHA-2; different construction; immune to SHA-2 weaknesses |
| BLAKE2b | 512-bit | Very fast | 256-bit security | 512-bit security | Password hashing, file integrity; faster than SHA-2 |
| BLAKE3 | 256-bit (extensible) | Extremely fast | 128-bit security | 256-bit security | General purpose; parallelizable; modern default |

### Hash Attack Types

| Attack | Description | Vulnerable Algorithms |
|---|---|---|
| Collision | Find `m1 ≠ m2` where `H(m1) = H(m2)` | MD5, SHA-1 |
| Birthday Attack | Statistical: collision found in `O(2^(n/2))` operations | All hash functions (inherent) |
| Length Extension | Append data to hash without knowing secret: `H(secret \| msg \| append)` | MD5, SHA-1, SHA-256, SHA-512 (not SHA-3, BLAKE2/3) |
| Pre-image | Find `m` given `H(m)` | Weakened in MD5/SHA-1 |

**Length Extension Mitigation**: Use **HMAC** instead of bare hash for authentication; or use SHA-3/BLAKE2/3 which are not vulnerable

### Password Hashing — Mandatory Use

**Never use** unsalted hashes or fast hashes (MD5, SHA-1, SHA-256) for passwords.

| Algorithm | Parameters | Notes |
|---|---|---|
| **Argon2id** | memory ≥19 MiB, iterations ≥2, parallelism ≥1 | **First choice** (NIST SP 800-63B recommends); winner of PHC 2015; memory-hard |
| **bcrypt** | cost factor ≥12 | Wide library support; 72-byte password limit (hash long passwords first); no memory hardness |
| **scrypt** | N=32768, r=8, p=1 minimum | Memory-hard; used in cryptocurrency; harder to configure correctly than Argon2id |
| **PBKDF2-HMAC-SHA256** | iterations ≥600,000 | NIST-approved; FIPS-compliant environments; not memory-hard (GPU-crackable at scale) |

**Salt requirements**: Minimum 128 bits; generated by CSPRNG; unique per password; stored alongside hash

### HMAC

**Construction**: `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))`

- Provides both **integrity** and **authentication** (requires shared key)
- Immune to length-extension attacks by construction
- Use `HMAC-SHA256` as the default; `HMAC-SHA384`/`HMAC-SHA512` for higher security

**Timing-safe comparison** — CRITICAL:

```python
import hmac
# CORRECT — constant-time comparison
if hmac.compare_digest(expected_tag, received_tag):
    ...
# WRONG — timing oracle — do not use
if expected_tag == received_tag:
    ...
```

### Key Derivation Functions (KDF)

| KDF | Purpose | When to Use |
|---|---|---|
| **HKDF** (RFC 5869) | Extract + Expand from high-entropy secret | Deriving multiple keys from a shared DH secret; TLS 1.3 key schedule |
| **PBKDF2** | Password → key | FIPS environments; pair with SHA-256 and ≥600k iterations |
| **Argon2id** | Password → key | Password storage and password-based key derivation; preferred over PBKDF2 |
| **scrypt** | Password → key | When memory-hardness required and Argon2 unavailable |
| **SP 800-108 KDF** | PRF-based key derivation from key material | Federal systems; deriving subkeys from master key |

**HKDF Usage** (two-step):
1. **Extract**: `PRK = HKDF-Extract(salt, IKM)` — condenses input key material into pseudorandom key
2. **Expand**: `OKM = HKDF-Expand(PRK, info, L)` — expands PRK to desired output length with context binding

---

## TLS / SSL

### Version History

| Version | Status | Issues |
|---|---|---|
| SSL 2.0 | **Disallowed** | Fundamental design flaws; DROWN attack |
| SSL 3.0 | **Disallowed** | POODLE attack; RFC 7568 deprecates |
| TLS 1.0 | **Deprecated** (RFC 8996) | BEAST attack; weak PRF; PCI DSS 4.0 forbids |
| TLS 1.1 | **Deprecated** (RFC 8996) | Limited improvements; still CBC; PCI DSS 4.0 forbids |
| TLS 1.2 | **Still acceptable** | Correct configuration required; see cipher suites below |
| TLS 1.3 | **Required for new systems** | Mandatory forward secrecy; encrypted handshake; removed weak algorithms |

### TLS 1.3 Improvements

- **1-RTT handshake** (down from 2-RTT in TLS 1.2): reduced latency
- **0-RTT early data**: allows sending data with first flight — **replay attack risk**; only for idempotent requests; require application-level replay protection
- **Mandatory forward secrecy**: all key exchange is ephemeral (ECDHE or DHE); no more static RSA key exchange
- **Removed weak algorithms**: no RC4, DES, 3DES, MD5, SHA-1, static RSA/DH, export ciphers
- **Encrypted handshake**: Certificate and most handshake messages are encrypted (post-ServerHello)
- **Simplified cipher suites**: Only 5 cipher suites; algorithm agility reduced to prevent downgrade

### TLS Cipher Suites

**TLS 1.3 Cipher Suites** (key exchange and certificate type negotiated separately):

| Cipher Suite | Encryption | MAC | Notes |
|---|---|---|---|
| TLS_AES_256_GCM_SHA384 | AES-256-GCM | SHA-384 | **Preferred** |
| TLS_CHACHA20_POLY1305_SHA256 | ChaCha20-Poly1305 | SHA-256 | **Preferred** — non-AES-NI hardware |
| TLS_AES_128_GCM_SHA256 | AES-128-GCM | SHA-256 | Acceptable |

**TLS 1.2 Recommended Cipher Suites** (in priority order):

```
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
```

**TLS 1.2 Cipher Suites to Disable**:
- Anything with `NULL`, `EXPORT`, `anon`, `DES`, `RC4`, `MD5`, `PSK` (without ECDHE), `SRP`, `3DES`
- Anything without `ECDHE` or `DHE` (no forward secrecy)

### Key Exchange

| Method | Groups | Notes |
|---|---|---|
| ECDHE | X25519 (preferred), X448, P-256, P-384 | Default in TLS 1.3; forward secrecy |
| DHE | RFC 7919 named groups (ffdhe2048 minimum) | Use ffdhe3072+ for new deployments |
| Static RSA | — | **Removed in TLS 1.3**; no forward secrecy |

### Certificate Validation

1. **Chain of trust**: Leaf cert → Intermediate CA(s) → Root CA (in trust store)
2. **Signature verification**: Each cert signed by issuer's private key; verify with issuer's public key
3. **Validity period**: Check `notBefore` and `notAfter`
4. **Revocation**:
   - **CRL** (Certificate Revocation List): Downloaded list of revoked certs; staleness risk
   - **OCSP** (Online Certificate Status Protocol): Real-time status check; privacy concern (CA sees queries)
   - **OCSP Stapling**: Server fetches OCSP response, staples to TLS handshake; recommended
5. **Certificate Transparency (CT)**: Verify cert is logged in CT log; detect misissuance

### Common TLS Attacks

| Attack | Version | Description | Mitigation |
|---|---|---|---|
| BEAST | TLS 1.0 | CBC IV predictability in block-mode; plaintext recovery | Disable TLS 1.0; use GCM |
| POODLE | SSL 3.0 / TLS | Padding oracle on CBC — SSLv3 version | Disable SSL 3.0; TLS_FALLBACK_SCSV |
| DROWN | SSL 2.0 | Decrypt RSA-encrypted TLS traffic via SSLv2 oracle | Disable SSL 2.0 on all servers |
| ROBOT | TLS 1.2 | Bleichenbacher oracle via RSA PKCS#1 v1.5 in TLS | Disable RSA key exchange; use ECDHE |
| SWEET32 | TLS 1.2 | Birthday attack on 64-bit block ciphers (3DES, Blowfish) | Disable 3DES; use AES |
| Lucky13 | TLS 1.2 | Timing attack on CBC MAC verification | Use GCM; constant-time MAC verification |
| Heartbleed | TLS (OpenSSL) | Memory disclosure via TLS Heartbeat extension (CVE-2014-0160) | Patch OpenSSL; reissue compromised certs |
| CRIME / BREACH | TLS | Compression oracle — leak secrets from compressed TLS | Disable TLS compression; BREACH mitigations |

### OpenSSL Commands

```bash
# Connect and show TLS 1.3 handshake details
openssl s_client -connect host:443 -tls1_3 -showcerts

# Show certificate details
openssl x509 -in cert.pem -noout -text

# List cipher suites
openssl ciphers -v 'HIGH:!aNULL:!MD5:!RC4'

# Generate RSA key and self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes

# Generate ECDSA key (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out ec-key.pem

# Verify certificate chain
openssl verify -CAfile ca-bundle.pem cert.pem

# Check OCSP status
openssl ocsp -issuer issuer.pem -cert cert.pem -url http://ocsp.example.com -resp_text

# Test specific TLS version
openssl s_client -connect host:443 -tls1_2
```

**testssl.sh**:
```bash
# Comprehensive TLS assessment
testssl.sh --parallel --html report.html --json-pretty report.json https://target.com

# Check specific vulnerability
testssl.sh --heartbleed --robot https://target.com
```

---

## PKI & Certificates

### X.509 Certificate Structure

| Field | Description |
|---|---|
| Version | v3 (virtually all modern certs) |
| Serial Number | Unique integer assigned by CA; must be random (RFC 5280 §4.1.2.2) |
| Signature Algorithm | Algorithm used to sign cert (e.g., `sha256WithRSAEncryption`, `ecdsa-with-SHA256`) |
| Issuer | CA's Distinguished Name (DN) |
| Validity | `notBefore` and `notAfter` timestamps |
| Subject | Entity's Distinguished Name (CN, O, OU, C, etc.) |
| Subject Public Key Info (SPKI) | Algorithm + public key |
| Extensions | SAN, Key Usage, EKU, Basic Constraints, AKI, SKI, CDP, OCSP, CT SCTs |

**Critical Extensions**

| Extension | Purpose | Notes |
|---|---|---|
| Subject Alternative Name (SAN) | DNS names, IPs, email the cert is valid for | CN alone deprecated; SAN required |
| Key Usage | What the key can do (Digital Signature, Key Encipherment, Certificate Sign) | Must be marked critical |
| Extended Key Usage (EKU) | Specific use cases (TLS server, client auth, code signing) | See table below |
| Basic Constraints | Is this cert a CA? If so, path length limit | Mark critical for CA certs |
| Authority Key Identifier (AKI) | Identifies issuing CA key | Links cert to issuer |
| Subject Key Identifier (SKI) | Identifies this cert's public key | Used in chain building |
| CRL Distribution Points (CDP) | URL to download CRL | Revocation checking |
| OCSP | URL for OCSP responder | Real-time revocation |
| Certificate Transparency SCTs | Proof of CT log submission | Required by major browsers |

### Key Usage vs Extended Key Usage

| Key Usage Value | EKU Value | Typical Use |
|---|---|---|
| Digital Signature | TLS Web Server Authentication | Server certificates in TLS |
| Digital Signature | TLS Web Client Authentication | Client certificate mTLS |
| Digital Signature | Code Signing | Software signing |
| Digital Signature | Email Protection (S/MIME) | Email encryption/signing |
| Key Encipherment | TLS Web Server Authentication | RSA server certs (key exchange) |
| Certificate Sign | — | CA certificates only |
| CRL Sign | — | CA certificates only |

### Certificate Chain

```
Root CA (self-signed, in OS/browser trust store)
  └── Intermediate CA (signed by Root)
        └── End-entity (Leaf) Certificate (signed by Intermediate)
```

- Root CA private key must be offline/air-gapped (HSM required for enterprise)
- Intermediate CA handles day-to-day issuance
- End-entity cert validity: max 397 days (browser/CA/B Forum Ballot SC-65)

### Certificate Transparency (CT)

- Public, append-only logs of all issued certificates
- CAs must submit certs to approved CT logs before issuance (Chrome requirement)
- **SCT** (Signed Certificate Timestamp): proof of log submission embedded in cert or via TLS extension
- **Monitor for misissuance**: `crt.sh` — search for domains; `certspotter`, `certstream` for real-time monitoring
- Use case: detect unauthorized certificate issuance for your domains

```bash
# Search CT logs for a domain
curl "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value'
```

### ACME Protocol (Let's Encrypt)

```bash
# HTTP-01 challenge (webroot)
certbot certonly --webroot -w /var/www/html -d example.com -d www.example.com

# DNS-01 challenge (wildcard certs)
certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cf.ini \
  -d example.com -d '*.example.com'

# Renew all certs
certbot renew --dry-run
```

### Internal PKI

**OpenSSL CA workflow**:
```bash
# Create Root CA
openssl genrsa -aes256 -out root-ca.key 4096
openssl req -new -x509 -days 3650 -key root-ca.key -out root-ca.crt -extensions v3_ca

# Create Intermediate CA
openssl genrsa -aes256 -out intermediate.key 4096
openssl req -new -key intermediate.key -out intermediate.csr
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 1825 \
  -notext -in intermediate.csr -out intermediate.crt

# Sign server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl ca -config intermediate-openssl.cnf -extensions server_cert \
  -days 365 -notext -in server.csr -out server.crt
```

**HashiCorp Vault PKI Secrets Engine**:
```bash
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal common_name="example.com" ttl=87600h
vault write pki/roles/example-dot-com allowed_domains="example.com" allow_subdomains=true max_ttl=72h
vault write pki/issue/example-dot-com common_name="server.example.com"
```

### Certificate Pinning

| Approach | Description | Risks |
|---|---|---|
| HPKP (HTTP Public Key Pinning) | **Deprecated** (removed from browsers 2018) | Catastrophic misconfiguration risk; HPKP suicide |
| Application-level pinning | Bundle expected cert/SPKI hash in app binary | Pins break on cert renewal; difficult to update; can be bypassed with Frida/SSL unpin |
| Trust-on-First-Use (TOFU) | Pin on first connection | Vulnerable to initial MITM |

**SPKI pinning (Python example)**:
```python
import ssl, hashlib, base64
cert = ssl.get_server_certificate(("example.com", 443))
# Hash the SubjectPublicKeyInfo
# Compare against pinned hash
```

### mTLS (Mutual TLS)

- Both client and server present and validate X.509 certificates
- Use cases: service-to-service auth (zero trust), API authentication, device identity

**Generate client cert**:
```bash
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client1/O=MyOrg"
openssl ca -config ca.cnf -extensions client_cert -days 365 -in client.csr -out client.crt
```

**nginx mTLS config**:
```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;
    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
}
```

---

## Key Management

### Key Lifecycle

```
Generate → Store → Distribute → Use → Rotate → Revoke → Destroy
```

| Phase | Controls |
|---|---|
| **Generate** | Use FIPS 140-2/3 validated RNG; generate in HSM where possible |
| **Store** | HSM for high-value keys; KMS-backed storage; never store in code/config |
| **Distribute** | Key wrapping (AES-KEY-WRAP or RSA-OAEP); TLS transport; never in plaintext |
| **Use** | Enforce key purpose (encryption vs signing); audit access |
| **Rotate** | Schedule rotation before expiry; immediate rotation on suspected compromise |
| **Revoke** | Revoke in KMS; publish CRL/OCSP for certificates; notify dependents |
| **Destroy** | Cryptographic erasure (overwrite key material); audit log destruction |

### HSM (Hardware Security Module)

**FIPS 140-3 Security Levels**:

| Level | Description |
|---|---|
| Level 1 | Software-only; no physical security |
| Level 2 | Tamper-evident hardware; role-based auth |
| Level 3 | Tamper-resistant; identity-based auth; key zeroization on intrusion |
| Level 4 | Complete physical protection; environmental attack resistance |

**Cloud HSM Options**:

| Service | Provider | Notes |
|---|---|---|
| AWS CloudHSM | AWS | Dedicated single-tenant HSM; FIPS 140-3 Level 3; customer manages keys |
| Azure Dedicated HSM | Azure | Thales Luna 7 devices; FIPS 140-2 Level 3 |
| Google Cloud HSM | GCP | Cloud KMS HSM-backed keys; FIPS 140-2 Level 3 |

### Cloud KMS

**AWS KMS**:
- **Customer Managed Keys (CMK)**: Customer controls key policy and rotation
- **AWS Managed Keys**: AWS manages; customer cannot rotate manually
- **Key policy**: Resource-based policy on CMK; combined with IAM policies
- **Envelope encryption**: Plaintext data → encrypted with DEK; DEK → encrypted with CMK in KMS
- Automatic annual rotation available for symmetric CMKs

```bash
# Encrypt data with KMS
aws kms encrypt --key-id alias/mykey --plaintext fileb://secret.txt --output json | jq '.CiphertextBlob'

# Generate DEK
aws kms generate-data-key --key-id alias/mykey --key-spec AES_256
```

**Azure Key Vault**:
- **HSM-backed keys**: FIPS 140-2 Level 2+ (Premium tier)
- Access policies: Vault-level (legacy) or Azure RBAC (recommended)
- Managed identities for keyless service auth

**GCP Cloud KMS**:
- **Key rings**: Logical grouping of keys (region-specific)
- **IAM bindings**: `cloudkms.cryptoKeyEncrypterDecrypter` role
- **Automatic rotation**: Configurable rotation period per key

### Envelope Encryption Pattern

```
Plaintext Data
      │
      ▼ encrypt with DEK (AES-256-GCM, generated in memory)
Encrypted Data ──────────────────────────────────────────► Store

DEK (32 bytes)
      │
      ▼ encrypt with KEK via KMS
Encrypted DEK ────────────────────────────────────────────► Store alongside Encrypted Data

// Decrypt:
Encrypted DEK → KMS.Decrypt(KEK) → DEK → Decrypt(Encrypted Data)
```

### Secret Management

| Tool | Key Feature |
|---|---|
| HashiCorp Vault | Dynamic secrets (generated on demand, auto-expiring); lease/renewal; AppRole/Kubernetes auth |
| AWS Secrets Manager | Automatic rotation for RDS, Redshift, DocumentDB; cross-account access |
| Azure Key Vault Secrets | Versioned secrets; managed identity access; soft delete and purge protection |
| GCP Secret Manager | Versioned secrets; customer-managed encryption; regional replication |

**HashiCorp Vault dynamic secrets example**:
```bash
vault secrets enable database
vault write database/config/mydb plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(db:3306)/" \
  username="vault" password="vaultpass"
vault write database/roles/readonly db_name=mydb \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT ON *.* TO '{{name}}'@'%';" \
  default_ttl="1h" max_ttl="24h"
vault read database/creds/readonly  # Returns temp credentials
```

### Key Rotation Guidelines

| Key Type | Rotation Frequency |
|---|---|
| TLS Session Keys | Per-session (ephemeral) |
| TLS Certificates | Annual (max 397 days for public certs) |
| Symmetric Encryption Keys (data at rest) | Annual or on compromise |
| API Keys / Secrets | 90 days; immediately on exposure |
| Root CA Keys | 10–20 years (offline; rarely) |
| SSH Host Keys | On host rebuild or annual |
| Code Signing Keys | Per CA/B Forum; 2–3 years typical |

### Shamir's Secret Sharing

- Splits a secret into `n` shares where any `k` shares reconstruct the secret (`k-of-n` threshold)
- Mathematical basis: polynomial interpolation over a finite field
- Use cases: Root CA private key custody (5-of-9 ceremony), disaster recovery credentials, high-value key backup
- Implementations: `ssss` CLI tool, HashiCorp Vault seal (Shamir unseal keys), AWS CloudHSM MofN

---

## Cryptographic Attacks Reference

### Padding Oracle Attacks

- **Mechanism**: If an oracle (error message, timing) reveals whether decrypted padding is valid, an attacker can decrypt arbitrary ciphertext byte-by-byte without the key
- **Vulnerable**: CBC mode decryption where padding errors are distinguishable from MAC errors
- **Examples**: POODLE (SSL 3.0), BEAST (TLS 1.0), CBC padding oracles in custom applications

**Mitigation**:
- Use **AEAD** (AES-GCM, ChaCha20-Poly1305) — no padding, authenticated
- If CBC required: **Encrypt-then-MAC** (not MAC-then-encrypt); verify MAC before decryption
- Return constant-time, constant-error responses

### Birthday Attacks

- **Basis**: Collision probability for a hash with `n`-bit output reaches ~50% after `2^(n/2)` operations
- **Impact**: For 64-bit block ciphers (3DES, Blowfish), birthday collision found after ~32 GiB of traffic (SWEET32)
- **Hash collision**: MD5 (2^64) → practical; SHA-1 (2^80) → broken (SHAttered); SHA-256 (2^128) → secure

**Mitigation**: Use ≥128-bit block ciphers (AES); use SHA-256+ for hashing

### Timing Attacks

- Measure how long cryptographic operations take to infer secret values
- **String comparison**: Early-exit comparison leaks length and content of secrets

```python
# VULNERABLE — timing oracle
def verify_token(expected, received):
    return expected == received  # Returns early on first mismatch

# SAFE — constant-time
import hmac
def verify_token(expected, received):
    return hmac.compare_digest(expected.encode(), received.encode())
```

- **RSA timing**: Square-and-multiply exponentiation timing; mitigated by blinding
- **Cache timing**: AES T-table lookups reveal key bits; mitigated by AES-NI

### Downgrade Attacks

- Adversary forces client/server to negotiate a weaker protocol version or cipher
- **TLS_FALLBACK_SCSV**: Pseudo-cipher suite added to ClientHello when client retries with lower version; server aborts if it supports higher version (RFC 7507)
- **Version pinning**: Reject TLS below 1.2 server-side; reject below 1.3 for new systems
- **Strict Transport Security (HSTS)**: Prevents HTTP downgrade for web traffic

### Quantum Threats Summary

| Algorithm | Quantum Attack | Impact | Post-Quantum Replacement |
|---|---|---|---|
| RSA-2048 | Shor's algorithm | **Broken** — polynomial time | ML-KEM (key exchange), ML-DSA (signatures) |
| ECC P-256 | Shor's algorithm | **Broken** — faster than RSA | ML-KEM, X25519+ML-KEM hybrid |
| AES-128 | Grover's algorithm | Security halved (~64-bit effective) | AES-256 |
| AES-256 | Grover's algorithm | Security halved (~128-bit effective) | AES-256 remains acceptable |
| SHA-256 | Grover's algorithm | Pre-image security halved (~128-bit) | SHA-384 or SHA-512 for long-term |
| HMAC-SHA256 | Grover's algorithm | Security reduction | Acceptable with AES-256 keys |

---

## Algorithm Selection Cheat Sheet

| Use Case | Recommended Algorithm | Key/Output Size | Notes |
|---|---|---|---|
| Symmetric encryption | AES-256-GCM | 256-bit key | AEAD; 96-bit nonce; 128-bit tag |
| Symmetric encryption (no AES-NI) | ChaCha20-Poly1305 | 256-bit key | AEAD; constant-time |
| Password storage | Argon2id | — | memory=19MiB, iter=2, para=1 |
| Password storage (FIPS) | PBKDF2-HMAC-SHA256 | — | ≥600,000 iterations |
| General hashing | SHA-256 / BLAKE3 | 256-bit output | SHA-256 for FIPS; BLAKE3 for speed |
| HMAC authentication | HMAC-SHA256 | ≥256-bit key | Timing-safe comparison |
| Key derivation from secret | HKDF-SHA256 | — | Extract + Expand; TLS 1.3 |
| Asymmetric key exchange | X25519 (ECDH) | 255-bit | TLS 1.3 default; forward secrecy |
| Post-quantum key exchange | ML-KEM-768 (Kyber) | — | NIST FIPS 203; use hybrid with X25519 |
| Digital signatures (general) | Ed25519 (EdDSA) | 255-bit | Deterministic; fast; SSH, JWT |
| Digital signatures (TLS) | ECDSA P-256 or RSA-PSS 3072 | — | ECDSA preferred |
| Post-quantum signatures | ML-DSA-65 (Dilithium) | — | NIST FIPS 204 |
| TLS configuration | TLS 1.3 | — | ECDHE + AES-256-GCM or ChaCha20 |
| Certificate validity | RSA-3072 or ECDSA P-256 | — | Max 397-day validity |
| Random number generation | OS CSPRNG | — | `os.urandom()`, `/dev/urandom`, `CryptGenRandom` |

---

## Do-Not-Use List

| Algorithm / Practice | Reason |
|---|---|
| DES | 56-bit key; broken in 1997; trivially brute-forced |
| 3DES / TDEA | SWEET32 birthday attack; deprecated by NIST 2024 |
| RC4 | Statistical biases; broken in WEP, WPA-TKIP, TLS; RFC 7465 prohibits |
| MD5 | Collision attacks practical since 2004; Flame malware used MD5 collision |
| SHA-1 | SHAttered collision 2017; deprecated in browsers, certificates, Git |
| RSA-PKCS#1 v1.5 encryption | Bleichenbacher padding oracle; ROBOT attack; use OAEP |
| ECB mode | Identical plaintext blocks → identical ciphertext; penguin diagram |
| Static DH / RSA key exchange | No forward secrecy; compromise of server key decrypts all past sessions |
| `random()` / `Math.random()` for crypto | Not cryptographically secure; predictable; use CSPRNG |
| Hardcoded keys/secrets in code | Version control exposure; cannot rotate; use secrets management |
| Non-random IVs/nonces | Predictable IVs in CBC allow BEAST; reused GCM nonces destroy security |
| Homegrown / roll-your-own crypto | Subtle implementation errors; use audited libraries (OpenSSL, libsodium, BoringSSL) |
| Export-grade algorithms (EXPORT) | FREAK, Logjam; 40-bit/512-bit key constraints; disable in server config |
| MD5/SHA-1 for password storage | Fast hash; GPU-crackable; use bcrypt, Argon2id, scrypt |

---

## NIST / Compliance Cross-Reference

| Standard | Scope |
|---|---|
| NIST SP 800-57 Part 1 Rev. 5 | Key management recommendations; algorithm selection; key size guidance |
| NIST FIPS 140-3 | Cryptographic module validation; HSM levels; approved algorithms |
| NIST FIPS 197 | AES specification |
| NIST SP 800-38A through 38D | Block cipher modes of operation (CBC, CTR, GCM) |
| NIST SP 800-131A Rev. 2 | Algorithm transitions; deprecation schedule (3DES, SHA-1, RSA-1024) |
| NIST SP 800-63B | Digital identity; password hashing requirements (Argon2id/PBKDF2) |
| NIST FIPS 203 | ML-KEM (Kyber) post-quantum key encapsulation |
| NIST FIPS 204 | ML-DSA (Dilithium) post-quantum signatures |
| NIST FIPS 205 | SLH-DSA (SPHINCS+) post-quantum signatures |
| NIST SP 800-208 | Recommendation for Stateful Hash-Based Signature Schemes (LMS/XMSS) |
| PCI DSS 4.0 | TLS 1.0/1.1 prohibited; strong cryptography requirements |
| MITRE ATT&CK T1552 | Unsecured Credentials — key management weaknesses |
| MITRE ATT&CK T1553 | Subvert Trust Controls — certificate/PKI attacks |
| MITRE ATT&CK T1557 | Adversary-in-the-Middle — TLS downgrade and MITM |
| RFC 8446 | TLS 1.3 specification |
| RFC 8996 | Deprecation of TLS 1.0 and TLS 1.1 |
| RFC 9180 | Hybrid Public Key Encryption (HPKE) |

---

*Reference compiled from NIST SP 800-57, NIST FIPS 140-3, NIST PQC FIPS 203/204/205, RFC 8446, RFC 8996, CA/Browser Forum Baseline Requirements, and MITRE ATT&CK.*
