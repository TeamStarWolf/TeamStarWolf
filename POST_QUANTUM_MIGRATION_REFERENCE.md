# Post-Quantum Cryptography Migration Reference

> **The post-quantum migration is a multi-year program, not a patch.** [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography) finalized the first three post-quantum standards — **FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)** — on August 13, 2024, and says organizations *"should begin applying these standards now."* Draft NIST guidance proposes deprecating quantum-vulnerable public-key cryptography (RSA, ECDSA, EdDSA, DH, ECDH) after **2030** and disallowing it after **2035**; NSA's CNSA 2.0 requires National Security Systems to finish even earlier, by **the end of 2033**.

The threat is not "a quantum computer might appear someday." It is that encrypted traffic recorded **today** can be decrypted **later** — so for any data whose confidentiality must outlive the arrival of a cryptographically relevant quantum computer, the deadline has already passed. This reference covers the migration *program*: risk framing, timelines, cryptographic discovery, crypto-agility, deployment status, PKI implications, and governance. For the algorithm internals (lattices, Shor's and Grover's algorithms, parameter sets), see the [Cryptography Reference §7.5–7.6](CRYPTOGRAPHY_REFERENCE.md) — this document deliberately does not duplicate them.

**Related:** [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md) · [Hardware Security](HARDWARE_SECURITY_REFERENCE.md) · [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) · [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) · [GRC & Compliance](GRC_COMPLIANCE_REFERENCE.md) · [Network Protocols](NETWORK_PROTOCOLS_REFERENCE.md)

| | |
|---|---|
| **Read this when** | scoping or chartering a PQC migration program, prioritizing which systems and data stores move to post-quantum crypto first, answering an auditor or executive about the 2030/2035 deadlines, or writing PQC questions into a vendor questionnaire |
| **Start at** | [Why this matters now: harvest now, decrypt later](#why-this-matters-now-harvest-now-decrypt-later) · [Step 1 — Cryptographic discovery and the CBOM](#step-1-cryptographic-discovery-and-the-cbom) · [Key dates quick reference](#key-dates-quick-reference) |

---

## Why this matters now: harvest now, decrypt later

**Harvest-now-decrypt-later (HNDL)** — also written "store now, decrypt later" — is the practice of recording encrypted traffic or exfiltrating ciphertext today with the intent of decrypting it once a **cryptographically relevant quantum computer (CRQC)** exists. It requires no new capability from the adversary beyond passive collection and patience, which is why it dominates PQC risk framing:

| Property | Consequence |
|---|---|
| **Passive** | No exploitation, no malware, no detection opportunity at collection time — a network tap or a compromised backbone suffices |
| **Retroactive** | Every TLS session, VPN tunnel, and encrypted archive recorded before you migrate is at risk *forever* |
| **Asymmetric-only** | Breaks the **key exchange and signatures** (RSA, ECDH, ECDSA), not the symmetric payload cipher — AES-256 retains a comfortable margin under Grover's algorithm |
| **Confidentiality-first** | Signatures can't be forged retroactively; recorded key exchanges *can* be broken retroactively — which is why key establishment migrates first |

> **Framing note:** HNDL is a risk model, not a catalogued adversary technique. **No official MITRE ATT&CK technique or mapping exists for harvest-now-decrypt-later** as of this writing — treat any such mapping you encounter as unofficial. Nation-state collection of encrypted traffic for future decryption is discussed in public advisories (e.g., the CNSA 2.0 FAQ and OpenSSH release notes both cite it as the motivating threat) as a strategic risk, not a technique ID.

### The migration math: Mosca's inequality

Michele Mosca's widely used test for "are we already late?":

```
   X  = secrecy lifetime      — how long the data must stay confidential
   Y  = migration time        — how long your organization needs to fully migrate
   Z  = time until a CRQC     — how long until an adversary can run Shor's algorithm at scale

                 if   X + Y > Z   →   you are already exposed

   |------ X (data must stay secret) ------|
                |------------- Y (your migration) -------------|
   |--------------------- Z (CRQC arrives) ----------|
   today                                             ▲
                                                     └── everything recorded before
                                                         migration completes is readable
```

You control **Y**. You can sometimes reduce **X** (data minimization, shorter retention). You do not control **Z** — and estimates for Z vary widely, which is precisely why the calculation is run against *your* data lifetimes rather than against a predicted CRQC date.

**Worked example — three assets, one inequality:**

| Asset | X (secrecy lifetime) | Y (realistic migration) | Verdict |
|---|---|---|---|
| **Patient records replicated between data centers** | Decades (lifetime confidentiality) | Re-key transport this year | X alone likely exceeds any plausible Z — **wave 1, now** |
| **Quarterly financials before release** | Weeks–months | Rides ecosystem TLS defaults | X is tiny — ecosystem pace is fine |
| **Firmware verifier in a device shipping 2027** | 15–20 yr service life, **fixed at design time** | Can't be migrated after shipping | Must ship PQC-capable signing/verification, or it is the 2040 incident |

**Who carries the most HNDL exposure** — sectors whose ordinary data has long X:

| Sector | Long-X data | Program driver |
|---|---|---|
| **Government / defense** | Classified material, CUI | CNSA 2.0 and M-23-02 are mandates, not suggestions |
| **Healthcare** | Records with lifetime confidentiality obligations | X measured in decades by default |
| **Financial services** | Account data, M&A material, long retention mandates | Regulator and ISAC attention already here |
| **Manufacturing / pharma / energy** | Trade secrets, designs, formulas with 10–30 yr commercial life | HNDL is industrial espionage with a delay timer |
| **Telecom / ISPs / cloud** | Everyone else's traffic in transit | Backbone links are the collection point — which is why transport migrates first |

**Do**
- Classify data by **required secrecy lifetime**, not just sensitivity tier — X is the variable most organizations have never measured.
- Treat migration duration (Y) honestly: federal planning assumes the transition runs **through 2035**; large-enterprise crypto transitions (3DES, SHA-1, TLS 1.0) historically took 10+ years.
- Prioritize **key establishment on long-haul links** (site-to-site VPN, replication traffic, backups in transit) — the highest-value HNDL collection targets.

**Don't**
- Wait for a CRQC announcement. The whole point of HNDL is that by then it is too late for everything already recorded.
- Model this as a CVE with a patch date. There is no patch event — there is a program with sequenced milestones.

---

## The standards at a glance

Algorithm internals, parameter sets, and security levels live in the [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md); this table is the program-level status board. All three finalized FIPS were published **August 13, 2024**.

| Standard | Algorithm (origin) | Type | Status (as of Sept 2026) |
|---|---|---|---|
| **[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)** | ML-KEM (CRYSTALS-Kyber) | Key encapsulation, Module-LWE lattice | **Final** — Aug 13, 2024. Parameter sets ML-KEM-512/768/1024 |
| **[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)** | ML-DSA (CRYSTALS-Dilithium) | Signature, module lattice | **Final** — Aug 13, 2024. ML-DSA-44/65/87 |
| **[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)** | SLH-DSA (SPHINCS+) | Signature, stateless hash-based | **Final** — Aug 13, 2024. 12 parameter sets |
| **HQC** | HQC (code-based) | Key encapsulation | **Selected** Mar 11, 2025 as the fifth algorithm (rationale in NIST IR 8545); draft FIPS still pending, **no FIPS number officially assigned** — "FIPS 207" in vendor blogs is speculation. NIST projected the final for ~2027 |
| **FIPS 206 (draft)** | FN-DSA (FALCON) | Signature, lattice (fast, compact) | **In the draft/approval process**; per a NIST presentation, submitted for approval Aug 28, 2025, final expected late 2026/early 2027. Its floating-point Gaussian sampling is the stated reason it lags |
| **[SP 800-227](https://csrc.nist.gov/Projects/post-quantum-cryptography/news)** | — | KEM usage recommendations | **Final** — Sept 18, 2025. The implementation/usage companion to FIPS 203 |
| **Signature "onramp"** | 14 → 9 candidates | Additional signatures | Round 2: 14 candidates ([IR 8528](https://www.nist.gov/news-events/news/2024/10/nist-announces-14-candidates-advance-second-round-additional-digital), Oct 24, 2024); Round 3: 9 candidates (IR 8610, May 14, 2026) |

Two program-level facts worth internalizing:

- **HQC exists because ML-KEM might not last.** NIST chose a code-based backup KEM *specifically because it is not lattice-based* — a hedge against a mathematical break of the entire lattice family. Your architecture should be able to absorb that swap (see [crypto-agility](#step-2-crypto-agility-architecture)).
- **Stateful hash-based signatures (LMS/XMSS, SP 800-208) were approved before all of this** and are already the CNSA 2.0-approved answer for software/firmware signing — the one place where signing keys must outlive everything else.

### Which algorithm for which job

| Job | Pick | Program notes |
|---|---|---|
| **TLS / SSH / VPN key establishment** | ML-KEM-768 in a hybrid group (`X25519MLKEM768`) | The deployed internet default; CNSA 2.0 environments require ML-KEM-1024. Usage guidance: SP 800-227 |
| **General-purpose signatures** (certificates, tokens, code) | ML-DSA — ML-DSA-65 as a balanced commercial default, ML-DSA-87 where CNSA 2.0 applies | Largest operational impact is signature size (see [PKI implications](#protocol-and-pki-implications)) |
| **Conservative, long-lived signing where size is tolerable** | SLH-DSA | Security rests only on hash-function assumptions — the most conservative choice — but signatures start at ~7.9 KB. Note: **excluded from NSS use** by CNSA 2.0 FAQ v2.1 |
| **Firmware / software signing** | LMS or XMSS (SP 800-208) | Approved now and mandated by CNSA 2.0. **Stateful:** reusing a one-time-signature state destroys the key, so state management belongs in an HSM-grade signer, never a stateless build farm. Multi-tree HSS/XMSS^MT is prohibited for NSS |
| **Size-constrained signatures** | Wait for FN-DSA (FIPS 206) | The compact-signature lattice option; not final, and NSA has said it will not join CNSA 2.0 |
| **A hedge against a lattice break** | HQC (once standardized) | The reason your [crypto-agility layer](#step-2-crypto-agility-architecture) must make KEM choice a configuration change |

---

## Government timelines

Three separate clocks are running. Know which one applies to you — and which parts are final versus proposed.

### NIST IR 8547 — the civilian/commercial clock (DRAFT)

[NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*](https://csrc.nist.gov/pubs/ir/8547/ipd) was released as an **Initial Public Draft on November 12, 2024** (comment period closed January 10, 2025) and — verified September 2026 — **remains a draft**. Its dates are **proposed guidance, not final NIST policy**, and must be labeled as such in any program documentation:

| Proposed milestone (draft) | What it covers |
|---|---|
| **Deprecated after 2030** | Quantum-vulnerable public-key algorithms at the 112-bit classical security strength — e.g., **RSA-2048**, ECDSA P-224 class. Deprecated = use is discouraged, risk is yours |
| **Disallowed after 2035** | **All** quantum-vulnerable public-key algorithms — RSA, ECDSA, EdDSA, DH, ECDH — *regardless of key size*. Disallowed = no longer permitted for federal use |

The 2035 endpoint aligns with the federal migration target set by NSM-10 and OMB M-23-02 (below). For commercial organizations, IR 8547's practical value is as **the defensible planning horizon**: auditors, cyber insurers, and customers will converge on 2030/2035 whether or not the draft is finalized unchanged.

### NSA CNSA 2.0 — the National Security Systems clock

The [Commercial National Security Algorithm Suite 2.0](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) (announced **September 2022**, FAQ updated to **v2.1 in December 2024**) is *mandatory* for National Security Systems and runs **ahead of** the NIST draft dates. CNSA 2.0 specifies only the **highest parameter sets**:

| CNSA 2.0 requirement | Selection |
|---|---|
| **Key establishment** | ML-KEM-1024 |
| **Digital signatures** | ML-DSA-87 |
| **Software/firmware signing** | LMS / XMSS (stateful hash-based, SP 800-208) — approved immediately |
| **Symmetric** | AES-256 |
| **Hashing** | SHA-384 / SHA-512 |

Per the CNSA 2.0 advisory and FAQ v2.1 (v2.1 specifics verified through multiple consistent secondary sources; spot-check the NSA PDF before quoting it in formal deliverables):

| Timeline | Milestone |
|---|---|
| **Immediately** | Begin CNSA 2.0 software/firmware signing (LMS/XMSS) |
| **Jan 1, 2027** | New NSS acquisitions must support CNSA 2.0 (FAQ v2.1) |
| **2030** | Software/firmware signing and **networking equipment** exclusively CNSA 2.0 |
| **2033** | Web browsers/servers, cloud services, and operating systems exclusively CNSA 2.0 |
| **Dec 31, 2033** | **Overall NSS transition complete** |

FAQ v2.1 fine print that changes designs: **SLH-DSA is excluded from NSS use** (despite being a final FIPS), the **HashML-DSA pre-hash mode is prohibited**, multi-tree **HSS/XMSS^MT is prohibited**, and NSA has stated **FN-DSA will not be added** to CNSA 2.0. On hybrids, NSA's position is that it *"has confidence in CNSA 2.0 algorithms and will not require NSS developers to use hybrid certified products for security purposes,"* while acknowledging some protocol standards may require hybrid-like constructions — a notably different posture from the hybrid-everywhere practice of the commercial internet (see [deployment status](#hybrid-key-exchange-in-the-wild)).

### Federal mandates — the governance template

| Instrument | Date | Requirement |
|---|---|---|
| **NSM-10** | May 4, 2022 | National Security Memorandum: US goal to migrate vulnerable federal cryptographic systems, targeting 2035 |
| **[OMB M-23-02](https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)** | Nov 18, 2022 | Agencies submit a **prioritized inventory of quantum-vulnerable cryptographic systems** to ONCD and CISA by May 4, 2023, and **annually thereafter until 2035**; funding assessments due within 30 days of each submission |
| **[Quantum Computing Cybersecurity Preparedness Act](https://www.congress.gov/bill/117th-congress/house-bill/7535)** (P.L. 117-260) | Dec 2022 | Codifies the inventory and migration-planning requirements in statute |
| **[CISA automated discovery strategy](https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf)** (in coordination with NSA and NIST, per M-23-02) | Sept 2024 | Federal blueprint for moving from manual inventories to **automated** cryptographic discovery and inventory tooling |

Even if you are not federal, M-23-02 is the best publicly available **program template**: prioritized inventory → annual refresh → funding ask tied to the inventory. Reuse the shape.

---

## Step 1 — Cryptographic discovery and the CBOM

You cannot migrate what you cannot find, and every organization that has run discovery has found cryptography where nobody expected it. The [NCCoE Migration to PQC project](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) (practice guide **SP 1800-38**, three volumes — A: executive summary, B: discovery-tool approach and architecture, C: interoperability and performance — all still **preliminary drafts**, built with 25+ industry collaborators) exists precisely because discovery is the hard, unglamorous first year of the program. A related draft, **CSWP 48**, maps PQC-migration capabilities onto cybersecurity risk frameworks.

### Where quantum-vulnerable cryptography hides

| Discovery domain | What you're looking for | How you find it |
|---|---|---|
| **Network in transit** | TLS/SSH/IPsec/VPN handshakes negotiating RSA/ECDH key exchange, classical-only cipher suites | Passive protocol inspection (Zeek/Suricata TLS metadata, JA3/JA4-adjacent handshake logging), load balancer and VPN concentrator config export |
| **PKI & certificates** | Every certificate's signature algorithm and key type; CA hierarchy; certificate lifetimes vs. the 2030/2035 horizon | Certificate transparency logs, internal CA database export, certificate lifecycle management (CLM) inventory |
| **Code & dependencies** | Calls into OpenSSL/BoringSSL/libsodium/BouncyCastle/`cryptography`; hardcoded algorithm choices; vendored crypto | SAST rules for crypto APIs, SCA/dependency scanning, grep for algorithm identifiers in IaC and config |
| **Keys & secrets** | Key stores, HSM partitions, KMS keys and their algorithms, SSH host/user keys, code-signing keys | KMS/HSM inventory APIs, [secrets management](SECRETS_MANAGEMENT_REFERENCE.md) platform export, SSH CA records |
| **Data at rest** | Encrypted archives, backups, and databases whose *content lifetime* exceeds the CRQC horizon | Data classification joined to encryption metadata — this is where X (secrecy lifetime) gets measured |
| **Protocols & firmware** | Embedded/OT devices with baked-in RSA, firmware update signature schemes, smartcards, TPM-bound keys | Firmware manifests, vendor questionnaires, [hardware security](HARDWARE_SECURITY_REFERENCE.md) inventory |
| **Third parties** | SaaS/vendor crypto posture, managed PKI, payment and identity providers | Vendor questionnaires tied to contract cycles (see [governance](#program-governance)) |

### CBOM — the cryptographic bill of materials

The inventory needs a machine-readable format, and one now exists: **[CycloneDX v1.6](https://cyclonedx.org/capabilities/cbom/)** (OWASP, April 2024; CBOM capability contributed by IBM Research) added the **CBOM** as a first-class object model for inventorying **algorithms, keys, certificates, crypto libraries, and protocols** — the cryptographic sibling of the SBOM you already collect for [supply chain security](SUPPLY_CHAIN_SECURITY_REFERENCE.md). CycloneDX 1.6 is also published as the **ECMA-424** standard, which is the citation procurement teams want. Cite 1.6/ECMA-424 as the standardized baseline; later CycloneDX versions may iterate on it.

**Do**
- Make the CBOM an **output of automation**, not a spreadsheet — the CISA strategy (Sept 2024) is explicit that manual inventories don't survive contact with reality. Regenerate per release/scan, and diff.
- Record for every asset: algorithm, key size/parameter set, protocol context, **who owns it**, and **the lifetime of the data it protects** — the last two fields drive all sequencing.
- Demand CBOMs (or at minimum a crypto disclosure) from vendors the same way you demand SBOMs.
- Feed the CBOM into your existing exposure workflow — discovery output with no prioritization step is the classic [CTEM](CTEM_REFERENCE.md) Stage-2 failure ("we found 40k crypto instances!").

**Don't**
- Scope discovery to "our web servers' TLS config." The long tail — firmware signing, document signing, database TDE, message queue encryption, service mesh mTLS — is where migrations stall in year four.
- Trust a library upgrade to change anything by itself. Discovery must capture *negotiated* algorithms (what actually runs), not just *supported* ones.

### Measuring what actually negotiates

Static inventory says what systems *support*; only telemetry says what they *use*. The same sources later become your progress metric ("% of traffic on hybrid PQ key exchange"):

| Telemetry source | What it gives you |
|---|---|
| **Zeek `ssl.log`** | Per-connection TLS version, cipher suite, and negotiated key-exchange group — ground truth for how much of your east-west and egress traffic is already hybrid PQ, and which endpoints never will be |
| **TLS termination / LB logs** | The negotiated group at your own edge — e.g., nginx exposes the negotiated curve/group via `$ssl_curve` — sliced by client population |
| **OpenSSH auth/server logs** | OpenSSH 10.1+ emits a warning when a **non-PQ key exchange** is negotiated; centralize it in the SIEM and treat sustained hits as a work queue of legacy clients |
| **Windows Schannel logging** | With Schannel event logging enabled, Event ID 36880 records the negotiated cipher suite per handshake on Windows TLS stacks |
| **Active spot checks** | `openssl s_client` (with explicit `-groups`) against your own endpoints to confirm a server actually negotiates `X25519MLKEM768`; scheduled scans of the certificate estate for signature algorithms and expiry-vs-2030/2035 |
| **KMS / HSM audit logs** | Which keys, of which algorithm, are actually being *used* — dormant classical keys retire on a different track than hot ones |

---

## Step 2 — Crypto-agility architecture

Crypto-agility is the ability to swap algorithms, parameters, and certificates **without redesigning the systems that use them**. It is the single highest-leverage investment of the whole program, because this migration will not be the last: HQC exists as a hedge against a lattice break, FIPS 206 is still coming, parameter sets may be revised, and the signature onramp will add algorithms. Build for the *next* swap while executing this one.

| Layer | Agility requirement | Concrete practice |
|---|---|---|
| **Application code** | No algorithm names in business logic | All crypto behind an internal abstraction/provider interface; algorithm choice injected from config or policy service, never hardcoded |
| **Protocol** | Negotiation, not pinning | Prefer protocols with algorithm negotiation (TLS 1.3 named groups, SSH kex lists); track and phase out protocols with fixed primitives |
| **Key & cert lifecycle** | Automated issuance/rotation | Certificate lifecycle management with automated renewal (ACME or equivalent) — if a cert swap requires a human, a PKI-wide algorithm swap is impossible |
| **Key hierarchy** | Re-wrap without re-encrypting the world | Envelope encryption everywhere: rotating the KEK to a PQC-protected exchange must not require touching every data object |
| **Policy** | Central algorithm policy, enforced | One place (policy service, config management baseline) that says what's allowed; systems consume it; exceptions are registered, not silent |
| **Testing** | Prove swap-ability before you need it | A recurring "algorithm fire drill": swap a non-production environment to new primitives, measure what breaks — handshake sizes, timeouts, middleboxes, hardcoded buffer lengths |
| **Vendors** | Contractual agility | Procurement language requiring PQC support timelines and configurable algorithms (see [governance](#program-governance)) |

**Do**
- Run the fire drill *now* with hybrid TLS groups — they're deployed, interoperable, and immediately expose the classic failure modes (middleboxes that choke on larger ClientHellos, fragmented handshakes, hardcoded size assumptions).
- Budget for **performance characterization**: ML-KEM is fast, but larger handshake messages change latency profiles on lossy/mobile links; SP 1800-38C exists because interoperability and performance are where theory meets production.
- Design certificate infrastructure for **dual chains** during transition (classical + PQC), since relying parties migrate at different speeds.

**Don't**
- Invent your own hybrid construction or KDF combination — use standardized constructions (RFC 10024 named groups for TLS, the SSH kex methods below) and the guidance in SP 800-227.
- Equate "the library supports ML-KEM" with agility. Agility is an *architecture property* measured by the cost of the swap, not a dependency version.
- Let exception-hunting stall the core: legacy systems that can't migrate get compensating isolation and a registered exception, while the 80% moves.

### The algorithm fire drill — what to actually test

Run against a representative non-production slice, on a schedule, and keep the results as the swap-ability scorecard:

- **Handshake integrity end-to-end**: hybrid groups negotiated through every proxy, WAF, TLS-inspection appliance, and load balancer in the real path — the classic failures are middleboxes that drop or mangle a ClientHello spanning multiple records.
- **Size assumptions**: certificate parsers, log pipelines, and message buffers that hardcoded "a signature is under 512 bytes"; database columns sized for classical keys; UDP paths near MTU.
- **Latency and failure behavior on bad networks**: lossy links, mobile clients, high-RTT paths — larger handshakes amplify retransmission cost; measure p95/p99 handshake time, not the mean.
- **Fallback behavior**: what actually happens when negotiation fails — a clean classical fallback (acceptable during transition, but logged), or an outage?
- **Rollback**: prove the swap is reversible in one config change. An algorithm change you can't roll back is a change you'll never be allowed to make in production.
- **Interoperability across your stack matrix**: the NCCoE built [SP 1800-38 Volume C](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) around interoperability and performance for exactly this reason — mixed library versions negotiating with each other is where surprises live.

---

## Step 3 — Migration sequencing by data lifetime

Not everything migrates at once, and the ordering is not arbitrary — it falls out of the HNDL math and the difference between confidentiality and authenticity:

```
   MIGRATE FIRST                                              MIGRATE ON SCHEDULE
   (retroactively breakable)                                  (not retroactively breakable)

   Key establishment ──► protects CONFIDENTIALITY             Signatures ──► protect AUTHENTICITY
   recorded today, broken later                               must only be unforgeable at
   = data disclosed                                           verification time

   Exception that jumps the queue: SIGNING KEYS WITH DECADE-SCALE LIVES
   (firmware/software signing, root CAs) — the signature must still be
   trustworthy when a CRQC exists, so they migrate EARLY despite being signatures.
```

| Priority | Asset class | Why | Target primitive |
|---|---|---|---|
| **1** | Key exchange on links carrying long-lived secrets (VPNs, replication, backup transport, messaging) | HNDL — recorded now, decrypted later | Hybrid ML-KEM key establishment (deployed today, see next section) |
| **2** | Data-at-rest key hierarchies for data with secrecy lifetime past ~2035 | Same HNDL logic, at rest | Re-wrap KEKs under PQC-protected key establishment; AES-256 payload |
| **3** | Firmware / software / code signing | Signing keys and verifiers live in devices for 10–20+ years; also the first CNSA 2.0 mandate (exclusive by 2030) | LMS/XMSS (SP 800-208) or ML-DSA, per ecosystem |
| **4** | Long-lived PKI (root/intermediate CAs, document signing, timestamping) | Roots issued now are trusted into the 2040s | ML-DSA chains, dual-chain transition (see [PKI implications](#protocol-and-pki-implications)) |
| **5** | Session authentication (TLS server certs, SSH host keys, tokens) | Short-lived; forgeable only *after* a CRQC exists | Migrate with ecosystem defaults before 2035 |
| **6** | Legacy/constrained systems that cannot change | Can't fix; must contain | Isolation, protocol gateways/tunneling through PQC-protected transports, registered risk acceptance |

The table is the whole strategy in miniature: **confidentiality with long X migrates now; authenticity with short X rides the ecosystem wave; long-lived signing is the exception that migrates early.**

---

## Hybrid key exchange in the wild

Hybrid key establishment — running a classical exchange (X25519/ECDH) *and* an ML-KEM encapsulation, then combining both secrets so the session is safe unless **both** are broken — is no longer experimental. It is the default on most of the internet you touched today:

| Ecosystem | Status (as of Sept 2026) |
|---|---|
| **TLS 1.3** | **[RFC 10024](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)** (Aug 2026, Proposed Standard) defines three hybrid named groups: `X25519MLKEM768` (codepoint 4588/0x11EC), `SecP256r1MLKEM768` (4587/0x11EB), `SecP384r1MLKEM1024` (4589/0x11ED) |
| **Browsers** | `X25519MLKEM768` default in **Firefox since 132** (Oct 2024) and **Chrome since 131** (Nov 2024); shipping in Safari |
| **Stacks & CDNs** | OpenSSL 3.5+, Go standard library, Cloudflare edge — making this the most widely deployed PQC on the internet; by late 2025 Cloudflare reported that a majority of human-initiated TLS traffic to its network negotiated hybrid PQ key exchange (verify current figures on Cloudflare Radar before quoting numbers) |
| **SSH** | [OpenSSH](https://www.openssh.org/pq.html): hybrid `sntrup761x25519` default since **9.0** (2022); `mlkem768x25519-sha256` added in 9.9 and **default since OpenSSH 10.0** (April 2025); **10.1 warns** when a non-PQ kex is negotiated, explicitly citing "store now, decrypt later." Note: SSH **host/user keys (signatures) remain classical** — PQ signature support for SSH is still in progress at the IETF |
| **Signal** | Hybrid PQ initial key agreement (**PQXDH**) deployed September 2023; **[SPQR](https://signal.org/blog/spqr/)** (Sparse Post-Quantum Ratchet, announced Oct 2, 2025) extends the Double Ratchet into a hybrid "Triple Ratchet" using ML-KEM, with formal analysis by Cryspen and research published at Eurocrypt/USENIX Security 2025 |
| **iMessage** | **[PQ3](https://security.apple.com/blog/imessage-pq3/)** announced Feb 21, 2024, shipped with iOS 17.4/macOS 14.4 (March 2024): hybrid ML-KEM-1024 + Curve25519 initial key establishment with periodic post-quantum rekeying |

**What this means for your program**

- **Client-side TLS PQC is largely done for you** — modern browsers already negotiate it. Your job is the **server side** (terminate hybrid groups at your edge/load balancers), **internal east-west traffic**, and everything that is not TLS.
- **Fleet SSH wins are one upgrade away**: OpenSSH ≥ 10.0 makes hybrid kex the default; enforce it via [hardening baselines](LINUX_HARDENING.md) and treat OpenSSH 10.1's non-PQ-kex warning as a detection signal worth centralizing from auth logs.
- **Hybrid vs. pure is a policy fork**: the commercial internet runs hybrid (defense in depth against both a CRQC and an ML-KEM break); CNSA 2.0 does not require hybrid for NSS and points to pure CNSA 2.0 algorithms. If you serve both worlds, your [agility layer](#step-2-crypto-agility-architecture) must express both policies.

### Migration patterns by system

| System | Current PQC path (Sept 2026) | Practical move |
|---|---|---|
| **Public TLS edge** | RFC 10024 hybrid groups; browsers negotiate by default | Enable hybrid groups on load balancers/CDN; measure negotiation rate; fix middleboxes that break on large ClientHellos |
| **Internal mTLS / service mesh** | Same TLS 1.3 mechanics; stack support via OpenSSL 3.5+, Go, modern proxies | Roll hybrid groups mesh-wide via proxy config; internal traffic is a prime HNDL target and entirely under your control |
| **SSH fleet** | OpenSSH ≥ 10.0 defaults to `mlkem768x25519-sha256` | Baseline the version; pin PQ kex in `sshd_config`/`ssh_config` via config management; watch for the 10.1 non-PQ warning. Host/user key *signatures* stay classical for now |
| **IPsec / IKEv2 VPN** | **[RFC 9370](https://datatracker.ietf.org/doc/rfc9370/)** (May 2023, Proposed Standard) adds multiple key exchanges to IKEv2 so classical (EC)DH can be combined with a PQC KEM | Site-to-site tunnels carry the longest-lived secrets in most estates — put RFC 9370/ML-KEM support at the top of the VPN vendor questionnaire |
| **End-user messaging** | Signal (PQXDH + SPQR) and iMessage (PQ3) already hybrid by default | Nothing to deploy; relevant as the design pattern for any in-house E2EE product |
| **Code/firmware signing** | LMS/XMSS approved now (SP 800-208); ML-DSA landing in signing ecosystems | Start with new device platforms and update channels — verifiers baked into hardware are unfixable later |
| **Public PKI / X.509** | RFC 9881 (ML-DSA certs, Oct 2025) and RFC 9935 (ML-KEM in X.509, Mar 2026) published; composite signatures still an Internet-Draft | Pilot ML-DSA issuance in a test CA; plan the dual-chain period; don't bet production on drafts |
| **DNSSEC** | No deployable PQC signing path yet — signature sizes break UDP answer sizes | Track IETF DNSOP work; this is a "ride the ecosystem" item, not a self-help item |
| **Data at rest / backups** | No protocol dependency — this is your key hierarchy | Re-wrap KEKs so key distribution/escrow runs over PQC-protected channels; payloads on AES-256 are already fine |

---

## Protocol and PKI implications

PQC's operational pain is not CPU — it's **bytes**. Public keys, ciphertexts, and especially signatures are one to two orders of magnitude larger than their elliptic-curve equivalents (sizes from the FIPS 203/204/205 tables):

| Object | Classical (Ed25519 / P-256) | ML-KEM-768 | ML-DSA-44 | ML-DSA-87 (CNSA 2.0) | SLH-DSA-128s |
|---|---|---|---|---|---|
| **Public/encapsulation key** | 32–65 B | 1,184 B | 1,312 B | 2,592 B | 32 B |
| **Ciphertext** | — | 1,088 B | — | — | — |
| **Signature** | ~64–72 B | — | 2,420 B | 4,627 B | ~7,856 B |

Consequences that show up in production:

| Area | Impact | What to do |
|---|---|---|
| **TLS handshakes** | Larger ClientHello/ServerHello; some legacy middleboxes and load balancers mishandle fragmented or >1-MTU handshake messages | Fire-drill hybrid groups through every middlebox path; fix or retire what breaks — this is cheap to test today |
| **Certificate chains** | A chain with 3 ML-DSA certs carries ~3× multi-KB signatures plus keys; TLS cert messages grow by an order of magnitude | Shorter chains, suppressed intermediates, careful root program planning |
| **UDP-based protocols** | **DNSSEC and IKE** struggle: signatures larger than path MTU force fragmentation/TCP fallback | Track IETF work per protocol; don't improvise |
| **X.509 standards** | **RFC 9881** (Oct 2025) defines ML-DSA identifiers for certificates/CRLs; **RFC 9935** (Mar 2026) defines ML-KEM in X.509; **composite ML-DSA signatures** (draft-ietf-lamps-pq-composite-sigs) — one cert object carrying classical+PQC — was still an Internet-Draft at last check; verify current status before designing around it |
| **CA/certificate ops** | Dual-chain period is unavoidable: classical chains for old relying parties, ML-DSA chains for new | Certificate lifecycle automation first (see [agility](#step-2-crypto-agility-architecture)); inventory relying parties that pin algorithms |
| **HSMs & FIPS 140-3** | Migration is gated on validated hardware: keys that must live in HSMs can only move when the HSM firmware supports (and is validated for) ML-KEM/ML-DSA | Put PQC support and validation timelines into HSM/KMS vendor questionnaires now; **check the NIST CMVP database for current validated modules** rather than trusting datasheets — validation lags algorithm support |
| **Constrained devices** | Smartcards, TPM-bound keys, IoT with KBs of RAM may never fit ML-DSA-87 | This is the long tail that ends in 2035, not 2030 — plan containment, not miracles |

Back-of-envelope for the chain problem: an ML-DSA-44 certificate carries ~1.3 KB of subject public key plus ~2.4 KB of issuer signature — roughly **3.7 KB of cryptographic material per certificate**, versus on the order of 0.1 KB for an ECDSA P-256 certificate. A three-certificate chain therefore grows by roughly 11 KB before counting OCSP staples and SCTs, each of which is also a signature. That arithmetic — not algorithm performance — is what drives the protocol work above.

---

## Common misconceptions

| Misconception | Reality |
|---|---|
| **"Quantum computers break all encryption"** | Shor's algorithm breaks the *public-key* algorithms (RSA, ECC, DH). Symmetric crypto and hashes keep large margins under Grover — AES-256 remains comfortable. See [Cryptography Reference §7.5](CRYPTOGRAPHY_REFERENCE.md) |
| **"We'll migrate when a CRQC is announced"** | HNDL means everything recorded before that day is already lost. The announcement is the *end* of the usable migration window, not the start |
| **"PQC is too slow for production"** | ML-KEM's compute cost is competitive with classical ECDH; the real cost is **bytes on the wire** — and it's already the default handshake in mainstream browsers, at internet scale |
| **"Hybrid is a temporary hack"** | Hybrid key agreement is a Proposed Standard (RFC 10024) and a deliberate defense-in-depth design: the session survives a break of *either* component. (NSS policy differs — CNSA 2.0 does not require hybrid) |
| **"QKD solves this"** | Quantum key distribution requires special-purpose links, does not provide authentication, and NSA's published guidance recommends PQC rather than QKD for securing National Security Systems |
| **"Buying a 'quantum-safe' product makes us quantum-safe"** | The migration is an inventory and architecture program. A product claim without a CBOM, configurable algorithms, and (for hardware) a FIPS 140-3 validation path is marketing |
| **"2035 is far away"** | Past crypto transitions (3DES, SHA-1, TLS 1.0) each took roughly a decade in large estates — that is *why* M-23-02 runs annual inventories until 2035. Y is almost always bigger than it looks |

---

## Program governance

The technical work fails without a program wrapper. M-23-02 (federal) and P.L. 117-260 define the shape; translate it inward:

| Program element | Federal version | Private-sector translation |
|---|---|---|
| **Executive mandate** | NSM-10 | Board/CISO-sponsored charter with the 2030/2035 horizon named explicitly |
| **Inventory** | Prioritized quantum-vulnerable system inventory to ONCD/CISA, annually until 2035 | CBOM-backed inventory, refreshed automatically, reported annually to risk committee |
| **Funding** | Assessment due within 30 days of each inventory submission | Tie the budget ask to the inventory delta — what moved, what's stuck, what it costs |
| **Prioritization** | Agency-prioritized by impact | Sequenced by data lifetime (Step 3), joined to your [CTEM](CTEM_REFERENCE.md) prioritization stage |
| **Vendor management** | Acquisition gates (CNSA 2.0: new NSS acquisitions support it by Jan 1, 2027) | PQC questions in every vendor questionnaire and renewal; contractual migration timelines |

**Vendor questionnaire — the six questions that matter**

1. Which products/services use quantum-vulnerable public-key cryptography, and where (key exchange, signatures, firmware signing)?
2. Can you provide a **CBOM** (CycloneDX 1.6/ECMA-424) or equivalent cryptographic disclosure?
3. What is your dated roadmap for FIPS 203/204/205 support, and is hybrid key establishment supported today?
4. Are algorithm choices **configurable by the customer**, or fixed in the product?
5. For hardware/HSM products: what is the FIPS 140-3 validation status and timeline for PQC algorithms?
6. What is your plan for products that cannot be upgraded (EOL, replacement, compensating guidance)?

**Do**
- Report progress in **milestones tied to the public dates** (2027 acquisition gates, 2030 deprecation/signing exclusivity, 2033 NSS completion, 2035 disallowance) — executives can anchor on external deadlines they didn't set.
- Track **% of inventory with a named owner and a migration wave** as the first-year metric; % actually migrated is a year-2+ metric (see [Security Metrics](SECURITY_METRICS_REFERENCE.md)).
- Keep an **exception register** with expiry dates for everything that can't move — silent exceptions become the 2035 crisis list.

**Don't**
- Run this as a side project inside the PKI team. The inventory spans network, code, vendors, OT, and data governance — it needs program management.
- Let "the dates are still draft" justify inaction. IR 8547's dates are proposed; CNSA 2.0's are not, HNDL doesn't wait for either, and the deployed internet has already moved.

### Metrics that show the migration is moving

Avoid vanity counts ("systems scanned"). Track movement against the external deadlines:

| Metric | Why it matters |
|---|---|
| **% of TLS/SSH sessions negotiating hybrid PQ key exchange** | The single most honest number in the program — measured from [telemetry](#measuring-what-actually-negotiates), not from config intent |
| **% of cryptographic inventory with owner + data-lifetime class + wave assignment** | Discovery without triage is the classic stall |
| **% of long-lifetime (X > ~10 yr) data stores with PQC-protected key establishment** | Directly tracks residual HNDL exposure |
| **Certificates expiring after 2030/2035 that are still classical** | Every one is a forced future migration event |
| **% of crypto operations behind the abstraction layer** | Agility as a measurable property, not an aspiration |
| **Vendor coverage: % of crypto-relevant vendors with a dated PQC roadmap on file** | The migration you can't do yourself |
| **Exception register: count and age** | Accumulating accepted risk, headed for the 2035 wall |

---

## The first 12 months

A starting cadence for an enterprise program, in the spirit of the [CTEM 90-day plan](CTEM_REFERENCE.md) but on migration timescales:

| Phase | Months | Do this |
|---|---|---|
| **Charter & baseline** | 1–2 | Name an exec sponsor; charter anchored explicitly to the 2030/2035 horizon; pick pilot scopes (public TLS edge, SSH fleet, one long-lived data store); stand up negotiated-algorithm telemetry before changing anything |
| **Discover** | 2–6 | CBOM tooling into CI and scanning; full certificate + KMS/HSM inventory; data-lifetime classification for crown-jewel stores; PQC questions into every vendor renewal |
| **Quick wins** | 3–6 | Enable hybrid TLS groups at the edge (clients already speak them); OpenSSH ≥ 10.0 in the fleet baseline; run the middlebox fire drill and fix what breaks |
| **Sequence** | 6–9 | Wave plan ordered by data lifetime (Step 3); exception register opened; budget request built from the inventory delta, M-23-02-style |
| **Execute wave 1** | 9–12 | Hybrid key establishment on long-haul confidentiality links (site-to-site VPN, replication, backup transport); re-wrap KEKs for long-lived data; pilot ML-DSA dual-chain issuance in a non-production CA |
| **Report & iterate** | 12+ | Annual inventory refresh and metrics to the risk committee; expand waves; revisit algorithm policy as HQC and FIPS 206 land |

> **Failure modes to avoid:** treating this as a TLS-only project; inventory-as-spreadsheet with no refresh; waiting for IR 8547 to finalize before starting; migrating signatures before key establishment (backwards for HNDL); buying "quantum-safe" products with no CBOM or validation evidence; letting stateful-signature state management ride on a stateless build farm; and having no answer for the constrained-device long tail until 2034.

---

## Key dates quick reference

| Date | Event | Status |
|---|---|---|
| **May 4, 2022** | NSM-10 sets federal PQC migration policy, targeting 2035 | Final |
| **Sept 2022** | NSA announces CNSA 2.0 | Final |
| **Nov 18, 2022** | OMB M-23-02: annual quantum-vulnerable inventories until 2035 | Final |
| **Dec 2022** | Quantum Computing Cybersecurity Preparedness Act (P.L. 117-260) | Law |
| **Aug 13, 2024** | FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) published | Final |
| **Sept 2024** | CISA automated discovery & inventory strategy (in coordination with NSA and NIST) | Final |
| **Oct 24, 2024** | Signature onramp round 2 — 14 candidates (IR 8528) | Final |
| **Oct–Nov 2024** | Firefox 132 / Chrome 131 default to X25519MLKEM768 | Shipped |
| **Nov 12, 2024** | NIST IR 8547 initial public draft | **Draft** |
| **Dec 2024** | CNSA 2.0 FAQ v2.1 | Final |
| **Mar 11, 2025** | HQC selected as fifth algorithm (backup KEM) | Selected; draft FIPS pending |
| **Apr 2025** | OpenSSH 10.0 defaults to mlkem768x25519-sha256 | Shipped |
| **Sept 18, 2025** | SP 800-227 (KEM recommendations) final | Final |
| **Oct 2025** | RFC 9881: ML-DSA in X.509 | Published (Proposed Standard) |
| **Mar 2026** | RFC 9935: ML-KEM in X.509 | Published (Proposed Standard) |
| **May 14, 2026** | Signature onramp round 3 — 9 candidates (IR 8610) | Final |
| **Aug 2026** | RFC 10024: hybrid TLS 1.3 key agreement (X25519MLKEM768 et al.) | Published (Proposed Standard) |
| **Jan 1, 2027** | New NSS acquisitions must support CNSA 2.0 (FAQ v2.1) | NSS mandate |
| **~2027** | HQC final standard (NIST projection); FIPS 206 (FN-DSA) expected | Projected |
| **2030** | IR 8547 (draft): 112-bit classical asymmetric (e.g., RSA-2048) deprecated · CNSA 2.0: signing & networking equipment exclusively PQC | Draft / NSS mandate |
| **Dec 31, 2033** | CNSA 2.0: NSS transition complete | NSS mandate |
| **2035** | IR 8547 (draft): all quantum-vulnerable public-key crypto disallowed · NSM-10/M-23-02 federal migration horizon | Draft / policy target |

---

## Program vocabulary

| Term | Meaning |
|---|---|
| **CRQC** | Cryptographically relevant quantum computer — one capable of running Shor's algorithm against real-world key sizes |
| **HNDL / SNDL** | Harvest- (store-) now-decrypt-later: recording ciphertext today to decrypt after a CRQC exists |
| **PQC** | Post-quantum cryptography — *classical* algorithms designed to resist quantum attack. Not the same thing as quantum cryptography/QKD |
| **KEM** | Key-encapsulation mechanism — the FIPS 203 primitive that replaces Diffie–Hellman-style key agreement |
| **Hybrid** | Combining a classical exchange and a PQC KEM so the session secret survives a break of either component |
| **Composite** | A single X.509 signature object binding classical + PQC signatures together (still an Internet-Draft) |
| **Dual chain** | Operating parallel classical and PQC certificate hierarchies during the transition |
| **CBOM** | Cryptographic bill of materials — machine-readable crypto inventory (CycloneDX 1.6 / ECMA-424) |
| **Crypto-agility** | Architecture property: the cost of swapping algorithms, parameters, or certificates without redesign |
| **Stateful HBS** | Stateful hash-based signatures (LMS/XMSS, SP 800-208) — secure only if one-time-signature state is never reused |
| **Mosca's inequality** | X + Y > Z ⇒ already exposed: secrecy lifetime + migration time vs. time to a CRQC |

---

## Sources

- NIST Post-Quantum Cryptography project — <https://csrc.nist.gov/projects/post-quantum-cryptography> · news — <https://csrc.nist.gov/Projects/post-quantum-cryptography/news>
- FIPS 203 (ML-KEM) — <https://csrc.nist.gov/pubs/fips/203/final> · FIPS 204 (ML-DSA) — <https://csrc.nist.gov/pubs/fips/204/final> · FIPS 205 (SLH-DSA) — <https://csrc.nist.gov/pubs/fips/205/final>
- HQC selection announcement (Mar 2025) — <https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption>
- NIST IR 8547 (initial public draft) — <https://csrc.nist.gov/pubs/ir/8547/ipd> · PDF — <https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf>
- NSA CNSA 2.0 FAQ — <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>
- OMB M-23-02 — <https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf>
- Quantum Computing Cybersecurity Preparedness Act (P.L. 117-260) — <https://www.congress.gov/bill/117th-congress/house-bill/7535>
- CISA (in coordination with NSA and NIST, per M-23-02), Strategy for Migrating to Automated PQC Discovery and Inventory Tools — <https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf>
- NCCoE Migration to PQC (SP 1800-38, CSWP 48) — <https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc> · FAQ — <https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/>
- Additional signatures onramp: round 2 (IR 8528) — <https://www.nist.gov/news-events/news/2024/10/nist-announces-14-candidates-advance-second-round-additional-digital> · round 3 (IR 8610) — <https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf>
- Hybrid TLS key agreement (RFC 10024, from draft-ietf-tls-ecdhe-mlkem) — <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
- Multiple Key Exchanges in IKEv2 (RFC 9370) — <https://datatracker.ietf.org/doc/rfc9370/>
- ML-DSA in X.509 (RFC 9881) — <https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/> · ML-KEM in X.509 (RFC 9935) — <https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/>
- OpenSSH post-quantum cryptography — <https://www.openssh.org/pq.html>
- Signal SPQR — <https://signal.org/blog/spqr/> · Apple iMessage PQ3 — <https://security.apple.com/blog/imessage-pq3/>
- CycloneDX CBOM (v1.6 / ECMA-424) — <https://cyclonedx.org/capabilities/cbom/>

---

*This is an independent practitioner summary. FIPS, NIST IR/SP, CNSA, OMB, IETF, and vendor documents cited above are the authoritative sources; NIST IR 8547 remains a draft and its dates are proposals, and CNSA 2.0 FAQ v2.1 details were cross-checked against secondary sources — verify against the primary PDFs before relying on them for compliance decisions. Not affiliated with or endorsed by NIST, NSA, CISA, or any vendor named.*
