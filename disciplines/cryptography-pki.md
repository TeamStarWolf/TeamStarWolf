# Cryptography & PKI

> The mathematical foundations of confidentiality, integrity, and authentication — from certificate lifecycle management to post-quantum readiness.

## What Cryptography & PKI Engineers Do

- Design and operate Public Key Infrastructure (PKI) including root CAs, intermediate CAs, and issuing CAs
- Manage the full certificate lifecycle: issuance, renewal, revocation, and monitoring
- Define cryptographic standards and enforce algorithm deprecation (MD5, SHA-1, 3DES, RSA-1024)
- Implement and manage Hardware Security Modules (HSMs) for key protection
- Advise on TLS configuration, cipher suite selection, and certificate pinning
- Plan migrations to post-quantum cryptographic algorithms
- Implement code signing, document signing, and email encryption (S/MIME)
- Manage secrets and key management systems (KMS, Vault)

---

## Core Standards & Frameworks

| Standard | Purpose |
|---|---|
| [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) | Recommendation for Key Management |
| [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) | Transitioning Cryptographic Algorithms and Key Lengths |
| [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography) | Post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA) |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | X.509 Certificate and CRL Profile |
| [CAB Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) | Public TLS certificate issuance requirements |
| [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) | Security Requirements for Cryptographic Modules |

---

## Free & Open-Source Tools

### Certificate Management

| Tool | Purpose | Notes |
|---|---|---|
| [OpenSSL](https://openssl.org/) | Swiss-army knife for crypto/PKI | Generate keys, CSRs, self-signed certs, inspect certs |
| [step-ca](https://smallstep.com/docs/step-ca/) | Private ACME CA | Automated cert issuance; ACME + SSH certs |
| [CFSSL](https://github.com/cloudflare/cfssl) | Cloudflare PKI toolkit | CA server + CLI; JSON-based |
| [cert-manager](https://cert-manager.io/) | Kubernetes cert automation | Automates Let's Encrypt + internal CA issuance |
| [Let's Encrypt / ACME](https://letsencrypt.org/) | Free public TLS certificates | Automated via Certbot or native ACME clients |
| [Certbot](https://certbot.eff.org/) | Let's Encrypt ACME client | Automated TLS for web servers |

### Key Management & Secrets

| Tool | Purpose | Notes |
|---|---|---|
| [HashiCorp Vault](https://www.vaultproject.io/) | Secrets + dynamic credentials + PKI | Gold standard for secrets management; PKI secrets engine |
| [OpenBao](https://openbao.org/) | Open-source Vault fork | Community-maintained Vault fork post-BSL license change |
| [EJBCA](https://www.ejbca.org/) | Enterprise Java CA | Full-featured open source CA; widely deployed |
| [Dogtag PKI](https://www.dogtagpki.org/) | Red Hat PKI | Full PKI system; FIPS-certified |

### TLS Analysis & Testing

| Tool | Purpose | Notes |
|---|---|---|
| [testssl.sh](https://testssl.sh/) | TLS/SSL server testing | Comprehensive cipher suite + vulnerability testing |
| [sslyze](https://github.com/nabla-c0d3/sslyze) | Python TLS analyzer | Programmatic TLS analysis; CI-friendly |
| [SSL Labs API](https://github.com/ssllabs/ssllabs-scan) | Qualys SSL Labs scanner | Industry-standard TLS grading |
| [crt.sh](https://crt.sh/) | Certificate Transparency log search | Monitor issued certs for your domains |
| [x509lint](https://github.com/kroeckx/x509lint) | X.509 certificate linter | Checks for CA/B Forum compliance |

### Code & Document Signing

| Tool | Purpose | Notes |
|---|---|---|
| [Sigstore / Cosign](https://docs.sigstore.dev/) | Container + artifact signing | Keyless signing via OIDC; supply chain security |
| [GPG / GnuPG](https://gnupg.org/) | Email + file signing/encryption | OpenPGP standard implementation |
| [osslsigncode](https://github.com/mtrojnar/osslsigncode) | Authenticode signing on Linux | Sign Windows executables on Linux |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Venafi](https://venafi.com/) | Machine identity management | Certificate + key lifecycle at enterprise scale |
| [DigiCert](https://www.digicert.com/) | Public + private PKI | CertCentral; IoT PKI; document signing |
| [Entrust](https://www.entrust.com/) | PKI + HSM + identity | Nshield HSMs; enterprise PKI services |
| [AWS KMS](https://aws.amazon.com/kms/) | Cloud key management | FIPS 140-2 Level 3; integrates with AWS services |
| [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/) | Cloud secrets + certificates | Managed HSM option; cert auto-renewal |
| [Google Cloud KMS](https://cloud.google.com/kms) | Cloud key management | Customer-managed encryption keys |
| [Thales Luna HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms) | Hardware Security Modules | Network HSM; FIPS 140-3 Level 3 |
| [Keyfactor](https://www.keyfactor.com/) | PKI + certificate management | EJBCA-based; Discovery + lifecycle automation |

---

## Key Concepts Reference

### Algorithm Status (2025)

| Algorithm | Status | Replacement |
|---|---|---|
| MD5 | ❌ Broken | SHA-256 or SHA-3 |
| SHA-1 (signatures) | ❌ Deprecated | SHA-256 |
| 3DES/DES | ❌ Deprecated | AES-256-GCM |
| RSA-1024 | ❌ Deprecated | RSA-2048 minimum, RSA-4096 preferred |
| RSA-2048 | ⚠️ Use with caution | Migrate to ECDSA P-256 or RSA-4096 |
| AES-128-GCM | ✅ Acceptable | — |
| AES-256-GCM | ✅ Recommended | — |
| ECDSA P-256 | ✅ Recommended | — |
| ChaCha20-Poly1305 | ✅ Recommended | — |
| RSA-OAEP (encryption) | ✅ Acceptable | Migrate to ML-KEM post-quantum |
| ML-KEM (Kyber) | ✅ Post-quantum | NIST FIPS 203 |
| ML-DSA (Dilithium) | ✅ Post-quantum | NIST FIPS 204 |

### TLS Configuration Best Practices

```
# Modern TLS (TLS 1.3 only — most restrictive)
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# Intermediate (TLS 1.2+1.3 — broader compatibility)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

---

## ATT&CK Coverage

Cryptography and PKI directly mitigate several ATT&CK techniques:

- **T1040** — Network Sniffing (strong TLS prevents credential interception)
- **T1557** — Adversary-in-the-Middle (certificate pinning, HSTS, HPKP)
- **T1552** — Unsecured Credentials (HSMs and KMS prevent key exposure)
- **T1553** — Subvert Trust Controls (CT logs, CAA records detect mis-issuance)
- **T1195.002** — Compromise Software Supply Chain (code signing with Cosign/Sigstore)

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GCED](https://www.giac.org/certifications/enterprise-defense-gced/) | GIAC | Enterprise defense including PKI |
| [CompTIA Security+](https://www.comptia.org/certifications/security) | CompTIA | Broad security including cryptography fundamentals |
| [CompTIA CySA+](https://www.comptia.org/certifications/cybersecurity-analyst) | CompTIA | Includes crypto analysis |
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC² | Domain 3: Security Architecture & Engineering (cryptography) |
| [Certified PKI Professional (CPP)](https://pkiinstitute.com/) | PKI Institute | Dedicated PKI practitioner certification |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Crypto 101](https://www.crypto101.io/) | Free book | Introductory cryptography; free PDF |
| [Dan Boneh's Cryptography Course](https://www.coursera.org/learn/crypto) | Free course | Stanford/Coursera; rigorous math-based intro |
| [Everything you need to know about certificates](https://smallstep.com/blog/everything-pki/) | Blog series | Smallstep PKI deep dive |
| [SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) | Reference | Qualys SSL Labs guide |
| [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography) | Reference | Post-quantum standardization status |
| [Applied Cryptography (Schneier)](https://www.schneier.com/books/applied-cryptography/) | Book | Classic reference |

---

## Related Disciplines

- [Supply Chain Security](supply-chain-security.md) — Code signing, SBOM, artifact provenance
- [DevSecOps](devsecops.md) — Secrets scanning in pipelines
- [Security Architecture](security-architecture.md) — TLS design, zero trust mutual auth
- [Cloud Security](cloud-security.md) — KMS, cloud certificate management
