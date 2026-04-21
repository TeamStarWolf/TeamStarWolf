# Cryptography & PKI

> The mathematical foundations of confidentiality, integrity, and authentication — from cipher algorithms and certificate lifecycle management to post-quantum readiness and cryptographic attacks.

Cryptography and Public Key Infrastructure (PKI) underpin nearly every security control in modern computing. Cryptography transforms data so that only authorized parties can read or verify it; PKI provides the trust infrastructure — certificate authorities, digital certificates, and revocation mechanisms — that makes asymmetric cryptography usable at scale. Practitioners span defensive roles (designing TLS configurations, operating CAs, managing HSMs, planning post-quantum migrations) and offensive roles (auditing implementations, attacking weak ciphers, abusing certificate authority trust chains, testing for downgrade vulnerabilities). Without sound cryptography, authentication, data-in-transit protection, code signing, and non-repudiation all fail.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Understand symmetric vs. asymmetric encryption, hashing, digital signatures, and TLS fundamentals. Learn what certificates are and how a CA hierarchy works. | [Crypto 101 (free book)](https://www.crypto101.io/) |
| Intermediate | Work through the Cryptopals challenges to understand real-world attacks (padding oracles, CBC bit-flipping, hash length extension). Learn to configure TLS correctly and analyze certificates with OpenSSL. | [Cryptopals Challenges](https://cryptopals.com/) |
| Advanced | Study post-quantum cryptography (ML-KEM, ML-DSA), AD CS attack paths (ESC1–ESC13 via Certipy/Certify), and protocol-level attacks (POODLE, BEAST, Bleichenbacher). Audit full PKI deployments. | [Dan Boneh's Cryptography Course (Stanford/Coursera)](https://www.coursera.org/learn/crypto) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| Cryptopals Challenges | https://cryptopals.com/ | Hands-on cryptographic attacks: padding oracles, bit-flipping, hash collisions |
| Dan Boneh's Cryptography (Coursera) | https://www.coursera.org/learn/crypto | Rigorous math-based introduction to symmetric/asymmetric cryptography |
| Crypto 101 | https://www.crypto101.io/ | Beginner-friendly cryptography; free PDF download |
| NIST PQC Project | https://csrc.nist.gov/projects/post-quantum-cryptography | Post-quantum algorithm standards and background reading |
| TryHackMe — Cryptography rooms | https://tryhackme.com/ | Guided labs: RSA, hashing, TLS |
| PentesterLab — Crypto challenges | https://pentesterlab.com/ | Practical attacks including padding oracles and hash collisions |
| PortSwigger Web Academy | https://portswigger.net/web-security | Includes padding oracle and JWT attacks in the crypto sections |

---

## Tools & Repositories

### Certificate & Key Management

| Tool | Purpose | Link |
|---|---|---|
| OpenSSL | Generate keys, CSRs, self-signed certs; inspect and test TLS | https://openssl.org/ |
| GnuPG | OpenPGP email encryption, file signing, key management | https://gnupg.org/ |
| cert-manager | Kubernetes-native certificate automation (Let's Encrypt, Vault) | https://github.com/cert-manager/cert-manager |
| HashiCorp Vault PKI | Secrets engine for internal PKI; dynamic certificate issuance | https://github.com/hashicorp/vault |
| step-ca | Private ACME CA with SSH certificate support | https://github.com/smallstep/certificates |
| CFSSL | Cloudflare PKI toolkit — CA server, CLI, JSON-based | https://github.com/cloudflare/cfssl |
| EJBCA | Full-featured open-source enterprise Java CA | https://github.com/Keyfactor/ejbca-ce |

### TLS Analysis & Offensive Testing

| Tool | Purpose | Link |
|---|---|---|
| testssl.sh | Comprehensive TLS/SSL server cipher suite and vulnerability testing | https://github.com/drwetter/testssl.sh |
| SSLyze | Programmatic TLS analysis; CI/CD-friendly Python library | https://github.com/nabla-c0d3/sslyze |
| Hashcat | Password and hash cracking; test hash strength (MD5, SHA-1 weaknesses) | https://github.com/hashcat/hashcat |
| Certipy | Active Directory Certificate Services (AD CS) attack and enumeration | https://github.com/ly4k/Certipy |
| Certify | AD CS enumeration and exploitation (.NET, Windows) | https://github.com/GhostPack/Certify |
| impacket | Protocol-level attacks; NTLM relay, SMB signing bypass | https://github.com/fortra/impacket |
| crt.sh | Certificate Transparency log search for issued certificates | https://crt.sh/ |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Venafi](https://venafi.com/) | Machine identity management | Certificate + key lifecycle at enterprise scale |
| [DigiCert](https://www.digicert.com/) | Public + private PKI, code signing | CertCentral; IoT PKI; document signing |
| [Entrust](https://www.entrust.com/) | PKI + HSM + identity | nShield HSMs; enterprise PKI services |
| [AWS CloudHSM](https://aws.amazon.com/cloudhsm/) | Cloud-based FIPS 140-3 Level 3 HSM | Customer-controlled key material in AWS |
| [Azure Dedicated HSM](https://azure.microsoft.com/en-us/products/azure-dedicated-hsm/) | Dedicated HSM in Azure | Thales Luna hardware; customer-exclusive |
| [Thales Luna HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms) | Network HSM | FIPS 140-3 Level 3; widely deployed in PKI roots |
| [Yubico YubiHSM 2](https://www.yubico.com/products/hardware-security-module/) | USB nano-HSM | Affordable HSM for small CA deployments |
| [Keyfactor](https://www.keyfactor.com/) | PKI + certificate lifecycle | EJBCA-based; discovery and lifecycle automation |
| [Google Cloud KMS](https://cloud.google.com/kms) | Cloud key management | Customer-managed encryption keys (CMEK) |

---

## Core Cryptography Concepts

### Symmetric Algorithms

| Algorithm | Status | Key Size | Notes |
|---|---|---|---|
| AES-256-GCM | Recommended | 256-bit | AEAD; preferred for data at rest and in transit |
| AES-128-GCM | Acceptable | 128-bit | AEAD; adequate for most use cases |
| ChaCha20-Poly1305 | Recommended | 256-bit | AEAD; strong on systems without AES hardware |
| 3DES (Triple-DES) | Deprecated | 112-bit effective | Sweet32 birthday attack; prohibited in TLS 1.3 |
| DES | Broken | 56-bit | Brute-forceable; never use |
| RC4 | Broken | Variable | Known biases; removed from all modern protocols |

### Asymmetric Algorithms

| Algorithm | Status | Recommended Key Size | Notes |
|---|---|---|---|
| RSA | Use with caution | 2048-bit minimum; 4096 preferred | Vulnerable to quantum; plan migration |
| ECC (NIST P-256) | Recommended | 256-bit (equivalent to RSA-3072) | ECDSA/ECDH; widely supported |
| Curve25519 / Ed25519 | Recommended | 256-bit | Modern, constant-time; excellent for TLS/SSH |
| Diffie-Hellman (finite field) | Deprecated | 1024-bit is broken; 2048 minimum | Prefer ECDH; Logjam attack affects 1024-bit DH |
| ML-KEM (Kyber) | Post-quantum | — | NIST FIPS 203; KEM for key encapsulation |
| ML-DSA (Dilithium) | Post-quantum | — | NIST FIPS 204; lattice-based digital signatures |
| SLH-DSA (SPHINCS+) | Post-quantum | — | NIST FIPS 205; hash-based signatures; conservative |

### Hashing Algorithms

| Algorithm | Status | Output Size | Notes |
|---|---|---|---|
| SHA-256 | Recommended | 256-bit | Standard choice; HMAC-SHA-256 for MACs |
| SHA-384 / SHA-512 | Recommended | 384/512-bit | Higher assurance; use in TLS 1.3 cipher suites |
| BLAKE3 | Recommended | 256-bit (default) | Fast, modern; excellent for software verification |
| SHA-3 (Keccak) | Recommended | Variable | NIST standardized; different construction than SHA-2 |
| SHA-1 | Deprecated | 160-bit | Collision attacks demonstrated (SHAttered); remove |
| MD5 | Broken | 128-bit | Practical collision attacks; never use for security |

### TLS Configuration

TLS 1.3 is the current standard. TLS 1.2 remains acceptable with careful cipher suite selection. SSL 3.0, TLS 1.0, and TLS 1.1 are deprecated and must not be used.

```nginx
# Modern — TLS 1.3 only
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# Intermediate — TLS 1.2 + 1.3
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

Certificate pinning restricts trust to specific certificates or public key hashes, preventing attacks using fraudulently issued certificates from other CAs.

### PKI Architecture

A CA hierarchy consists of a **root CA** (offline, air-gapped), **intermediate CAs** (online but restricted), and **issuing CAs** that sign end-entity certificates. Revocation is handled by CRLs (Certificate Revocation Lists, batch-published) or OCSP (Online Certificate Status Protocol, real-time). Certificate Transparency (CT) logs provide public, append-only audit trails of all issued certificates, enabling detection of mis-issuance.

---

## Offensive Perspective — Attacks on Cryptography

Understanding how cryptographic systems are attacked is essential for both building robust systems and conducting security assessments.

| Attack | Description | Affected Systems |
|---|---|---|
| POODLE | Padding Oracle On Downgraded Legacy Encryption — exploits CBC padding in SSL 3.0 | SSL 3.0, TLS with CBC padding |
| BEAST | Browser Exploit Against SSL/TLS — IV prediction in TLS 1.0 CBC | TLS 1.0 with CBC cipher suites |
| CRIME / BREACH | Compression ratio side-channel leaks plaintext secrets | TLS compression (CRIME), HTTP compression (BREACH) |
| DROWN | Cross-protocol attack using weak SSLv2 to decrypt TLS | Servers sharing keys across SSLv2 and TLS |
| Downgrade attacks | Force negotiation of weaker protocol/cipher; FREAK, Logjam | Any TLS deployment without min-version enforcement |
| Padding oracle | Distinguish valid/invalid padding reveals plaintext byte-by-byte | CBC-mode symmetric encryption |
| Bleichenbacher attack | RSA PKCS#1 v1.5 oracle — adaptive chosen ciphertext on RSA | RSA-based TLS key exchange (PKCS#1 v1.5) |
| Certificate forgery | Exploit weak CA controls or MD5/SHA-1 collisions to forge certificates | Public PKI trust chains |
| CA compromise | Compromising an intermediate or root CA allows issuing fraudulent certs | Entire CA's trust hierarchy |
| AD CS ESC1–ESC8 | Active Directory Certificate Services misconfigurations enabling privilege escalation | On-premises PKI in Windows AD environments |
| Key theft | Extracting private keys from memory, unencrypted key stores, or weak HSM access | Any system storing keys outside an HSM |
| Weak PRNG | Predictable randomness in key/nonce generation | Any cryptographic key generation without proper entropy |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| SC-8 | System & Communications Protection | Transmission confidentiality and integrity — mandate TLS 1.2+ |
| SC-12 | System & Communications Protection | Cryptographic key establishment and management policies |
| SC-13 | System & Communications Protection | Approved cryptographic algorithms (AES, SHA-2, approved PQC) |
| SC-17 | System & Communications Protection | Public key infrastructure certificates — CA hierarchy and certificate issuance |
| SC-28 | System & Communications Protection | Protection of information at rest — AES-256 encryption of stored data |
| SC-23 | System & Communications Protection | Session authenticity — TLS session establishment and certificate validation |
| SC-5 | System & Communications Protection | Denial-of-service protection — TLS renegotiation controls |
| IA-5 | Identification & Authentication | Authenticator management — certificate-based authentication, key rotation |
| IA-7 | Identification & Authentication | Cryptographic module authentication — FIPS 140-3 validated modules |
| SI-7 | System & Information Integrity | Software, firmware, and information integrity — code signing verification |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Credential Access | Strong TLS 1.3 with ECDHE prevents credential interception |
| [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | Private Keys | Credential Access | Attackers steal private keys from disk or memory; HSMs prevent this |
| [T1553.004](https://attack.mitre.org/techniques/T1553/004/) | Install Root Certificate | Defense Evasion | Adversaries install rogue CA certs to enable MITM; CT logs detect mis-issuance |
| [T1588.004](https://attack.mitre.org/techniques/T1588/004/) | Digital Certificates | Resource Development | Attackers obtain fraudulent certificates for phishing infrastructure |
| [T1600](https://attack.mitre.org/techniques/T1600/) | Weaken Encryption | Defense Evasion | Downgrade attacks (POODLE, FREAK, Logjam) weaken negotiated cipher suites |
| [T1599](https://attack.mitre.org/techniques/T1599/) | Network Boundary Bridging | Defense Evasion | Attackers exploit weak TLS to bridge network boundaries |
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Credential Access / Collection | Certificate pinning, HSTS, and HPKP prevent AiTM; Bleichenbacher exploits AiTM position |
| [T1185](https://attack.mitre.org/techniques/T1185/) | Browser Session Hijacking | Collection | BEAST and CRIME leverage browser TLS sessions to extract cookies/secrets |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC² | Domain 3: Security Architecture & Engineering — deep cryptography coverage |
| [CCSP](https://www.isc2.org/Certifications/CCSP) | ISC² | Cloud security including cloud key management, HSMs, certificate management |
| [SSCP](https://www.isc2.org/Certifications/SSCP) | ISC² | Systems Security Certified Practitioner — cryptography fundamentals |
| [GCED](https://www.giac.org/certifications/enterprise-defense-gced/) | GIAC | Enterprise defense including PKI operations |
| [CEH](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/) | EC-Council | Includes cryptanalysis and cryptographic attack techniques |
| [CompTIA Security+](https://www.comptia.org/certifications/security) | CompTIA | Broad security including cryptography fundamentals |
| [Certified PKI Professional (CPP)](https://pkiinstitute.com/) | PKI Institute | Dedicated PKI practitioner certification |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Serious Cryptography (Aumasson)](https://nostarch.com/seriouscrypto) | Book | Practical modern cryptography with real-world attack context |
| [Applied Cryptography (Schneier)](https://www.schneier.com/books/applied-cryptography/) | Book | Classic reference covering protocols and algorithms |
| [Cryptopals Challenges](https://cryptopals.com/) | Hands-on labs | Attack-focused; padding oracles, CBC bit-flipping, stream cipher nonce reuse |
| [Dan Boneh's Cryptography Course](https://www.coursera.org/learn/crypto) | Free course | Stanford/Coursera; rigorous mathematical foundations |
| [SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) | Reference | Qualys SSL Labs guide to TLS configuration |
| [NIST SP 800-57 Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) | Standard | Key management recommendations; algorithm lifetimes |
| [Everything About Certificates (Smallstep)](https://smallstep.com/blog/everything-pki/) | Blog series | Deep-dive PKI from a practitioner perspective |
| [AD CS Attack Guide (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2) | Research paper | ESC1–ESC8 AD Certificate Services attack paths |

---

---

## Cryptography Fundamentals

**Symmetric Encryption**

| Algorithm | Key Size | Mode | Use Case | Notes |
|---|---|---|---|---|
| AES-128-GCM | 128-bit | GCM (AEAD) | TLS 1.3, disk encryption, API encryption | Best for most uses; authenticated encryption |
| AES-256-GCM | 256-bit | GCM | High-security requirements, post-quantum margin | FIPS 140-3 approved; minimal performance cost over AES-128 |
| AES-128-CBC | 128-bit | CBC | Legacy; widely supported | Requires separate MAC; BEAST attack on old TLS; no auth encryption |
| ChaCha20-Poly1305 | 256-bit | Stream+MAC | Mobile/low-power devices | TLS 1.3 alternative to AES-GCM; faster on devices without AES hardware instructions |
| 3DES | 168-bit effective | CBC | Legacy mainframe, some payment HSMs | Deprecated; Sweet32 attack; avoid in new systems |
| DES | 56-bit | CBC | Do not use | Trivially broken (56-bit key) |

**Asymmetric Encryption**

| Algorithm | Key Size | Use Case | Post-Quantum Safe? |
|---|---|---|---|
| RSA-2048 | 2048-bit | TLS cert signing, email encryption | No (Shor's algorithm) |
| RSA-4096 | 4096-bit | High-security signing | No (still Shor's) |
| ECDSA P-256 | 256-bit | TLS certificates, code signing | No |
| ECDH P-256 | 256-bit | Key exchange (TLS) | No |
| Ed25519 | 255-bit | SSH keys, JWT signing, certificate signing | No |
| ML-KEM (CRYSTALS-Kyber) | Various | Post-quantum key encapsulation | YES (NIST FIPS 203) |
| ML-DSA (CRYSTALS-Dilithium) | Various | Post-quantum digital signatures | YES (NIST FIPS 204) |

**Hash Functions**

| Function | Output | Use | Status |
|---|---|---|---|
| SHA-256 | 256-bit | Integrity, digital signatures, certificates | Current standard |
| SHA-384/512 | 384/512-bit | High-security environments, NSA Suite B | Current standard |
| SHA3-256 | 256-bit | Alternative to SHA-2 | NIST approved |
| bcrypt | 60 chars | Password hashing | Recommended; auto-salted |
| Argon2id | Variable | Password hashing | NIST recommended 2023; PHC winner |
| MD5 | 128-bit | Checksums only (not security) | Cryptographically broken for signatures |
| SHA-1 | 160-bit | Deprecated legacy | Broken (SHAttered attack 2017); do not use |

**Common Crypto Mistakes**

| Mistake | Correct Approach | Vulnerability |
|---|---|---|
| ECB mode for block cipher | Use GCM or CBC+HMAC | ECB blocks reveal patterns (penguin attack) |
| MD5/SHA1 for password storage | bcrypt, Argon2id, scrypt | Rainbow table attacks; collision attacks |
| Weak random for crypto | `os.urandom()`, `SecureRandom`, `crypto.randomBytes()` | Predictable keys |
| Self-rolled crypto | Use OpenSSL, libsodium, Bouncy Castle | Subtle flaws in custom implementations |
| Hardcoded encryption key | Key management service (Vault, KMS) | Key exposure = all data exposed |
| No IV or static IV in CBC | Random IV per encryption operation | Duplicate ciphertext reveals duplicate plaintext |

---

## PKI and Certificate Lifecycle

**Certificate Authority Hierarchy**
```
Root CA (offline, air-gapped, HSM-backed)
└── Intermediate CA 1 (online, issues TLS certificates)
    ├── *.example.com (TLS leaf cert)
    └── code-signing.example.com (code signing cert)
└── Intermediate CA 2 (issues client auth certificates)
    └── user@example.com (client auth cert)
```

**Certificate Profiles**

| Type | Key Usage | Extended Key Usage | Common Use |
|---|---|---|---|
| TLS Server | Digital Signature, Key Encipherment | Server Authentication (1.3.6.1.5.5.7.3.1) | HTTPS web servers |
| TLS Client | Digital Signature | Client Authentication (1.3.6.1.5.5.7.3.2) | mTLS, ZTNA |
| Code Signing | Digital Signature | Code Signing (1.3.6.1.5.5.7.3.3) | Software signing |
| Email (S/MIME) | Digital Signature, Key Encipherment | Email Protection (1.3.6.1.5.5.7.3.4) | Encrypted/signed email |
| Document Signing | Non-Repudiation | Document Signing | PDF signing |

**Certificate Transparency (CT)**
- All public TLS certs must be logged in CT logs (since 2018)
- CT log: Public append-only ledger; anyone can query
- crt.sh: Query CT logs for certificates issued for a domain — attackers use for recon!
- Defense: Monitor CT logs for unauthorized certificates for your domain (crt.sh, Facebook CT Monitor)

**ACME Protocol (Let's Encrypt)**
```bash
# Certbot — automated certificate management
certbot --nginx -d example.com -d www.example.com

# Wildcard certificate (DNS challenge required)
certbot certonly --manual --preferred-challenges dns -d "*.example.com"

# Auto-renewal (add to cron)
0 3 * * * certbot renew --quiet

# Testing with staging environment
certbot --staging --nginx -d example.com
```

**Certificate Pinning**
- HPKP (deprecated): HTTP header pinning; catastrophic if pin changed incorrectly; removed from browsers
- Application-level pinning: Mobile apps pin expected cert hash; bypass requires repackaging
- CAA (Certification Authority Authorization) DNS record:
```
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issuewild ";"  (no wildcard certs allowed)
example.com. CAA 0 iodef "mailto:security@example.com"
```

---

## TLS Hardening Reference

**TLS Configuration Best Practices (Nginx)**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;  # TLS 1.3 handles this
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;         # Disable TLS session tickets (forward secrecy)
ssl_stapling on;                 # OCSP stapling
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
```

**Testing TLS Configuration**
```bash
# SSLyze (Python)
sslyze target.com:443 --regular

# testssl.sh
./testssl.sh target.com:443

# nmap TLS scan
nmap --script ssl-enum-ciphers -p 443 target.com

# Online: ssllabs.com/ssltest
```

---

## Post-Quantum Cryptography

**NIST Post-Quantum Standards (2024)**
- FIPS 203 (ML-KEM / Kyber): Key encapsulation; replace RSA/ECDH in key exchange
- FIPS 204 (ML-DSA / Dilithium): Digital signatures; replace RSA/ECDSA
- FIPS 205 (SLH-DSA / SPHINCS+): Hash-based signatures; backup when lattice math broken

**Migration Strategy**
- Crypto-agile architecture: Cipher suites parameterized; swap without rewriting system
- Hybrid mode: Combine classical + post-quantum key exchange (X25519 + Kyber) — defeats both attacks
- Timeline: "Store now, decrypt later" attacks happening now; migrate sensitive data within 5 years
- TLS 1.3 + Kyber: Chrome and major browsers experimenting with hybrid X25519Kyber768

## Related Disciplines

- [Supply Chain Security](supply-chain-security.md) — Code signing, SBOM, artifact provenance
- [DevSecOps](devsecops.md) — Secrets scanning, certificate management in pipelines
- [Security Architecture](security-architecture.md) — TLS design, zero trust mutual auth
- [Cloud Security](cloud-security.md) — KMS, cloud certificate management, CloudHSM
- [Hardware Security](hardware-security.md) — HSMs, TPMs, hardware-backed key storage
- [Identity & Access Management](identity-access-management.md) — Certificate-based authentication, PKI-backed MFA
