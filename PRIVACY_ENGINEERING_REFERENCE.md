# Privacy Engineering Reference

> **Privacy Engineering** — comprehensive technical and regulatory reference covering GDPR, CCPA/CPRA, global privacy laws, Privacy by Design, anonymization, pseudonymization, consent management, DPIA, and privacy-preserving engineering patterns.

**Key frameworks**: GDPR (EU) · CCPA/CPRA (California) · PIPEDA (Canada) · LGPD (Brazil) · HIPAA (US) · ISO 29100 · NIST Privacy Framework
**Technical controls**: pseudonymization · anonymization · tokenization · field-level encryption · differential privacy · PII detection · DLP
**Engineering practices**: Privacy by Design · LINDDUN threat modeling · ROPA · DPIA · privacy audit logging · consent management platforms

---

## Table of Contents

1. [Privacy Fundamentals](#1-privacy-fundamentals)
2. [GDPR Deep Dive](#2-gdpr-deep-dive)
3. [CCPA / CPRA](#3-ccpa--cpra)
4. [Global Privacy Regulations](#4-global-privacy-regulations)
5. [Privacy by Design — 7 Principles](#5-privacy-by-design--7-principles)
6. [Data Classification & ROPA](#6-data-classification--records-of-processing-activity-ropa)
7. [Technical Privacy Controls](#7-technical-privacy-controls)
8. [Privacy Engineering in APIs](#8-privacy-engineering-in-apis)
9. [Privacy Impact Assessment (PIA / DPIA)](#9-privacy-impact-assessment-pia--dpia)
10. [International Data Transfers](#10-international-data-transfers)
11. [Privacy Compliance Program](#11-privacy-compliance-program)

---

## 1. Privacy Fundamentals

### Privacy vs Security

| Dimension | Security | Privacy |
|-----------|----------|---------|
| Goal | Protect data from unauthorized access | Control how personal data is collected, used, shared |
| Threat actor | External attacker / insider | The organization itself (may misuse data legitimately obtained) |
| Legal basis | Generally no single law mandates it | GDPR, CCPA, HIPAA impose specific obligations |
| User control | User typically has no control | User has rights (access, erasure, portability) |
| Failure mode | Breach / unauthorized disclosure | Unlawful processing, purpose creep, consent violation |

> Security is a **necessary but not sufficient** condition for privacy. You can have strong security and still violate privacy (e.g., sharing data with third parties without consent).

---

### Key GDPR Definitions

| Term | Definition | Article |
|------|-----------|---------|
| **Personal data** | Any information relating to an identified or identifiable natural person (data subject) | Art. 4(1) |
| **Sensitive data** | Special categories: racial/ethnic origin, political opinions, religious beliefs, biometric/genetic data, health, sex life/orientation, trade union membership | Art. 9 |
| **Data subject** | The natural person to whom personal data relates | Art. 4(1) |
| **Controller** | Entity that determines purposes and means of processing | Art. 4(7) |
| **Processor** | Entity that processes data on behalf of the controller | Art. 4(8) |
| **DPO** | Data Protection Officer — mandatory for public authorities, large-scale systematic monitoring, or large-scale sensitive data processing | Art. 37 |
| **Pseudonymization** | Processing personal data so it cannot be attributed to a specific person without additional information (kept separately) | Art. 4(5) |
| **Anonymization** | Irreversible de-identification — no longer personal data, GDPR does not apply | Recital 26 |

---

### PII vs Personal Data

**PII (US concept)**: Directly identifies an individual — name, SSN, passport number, biometric data.

**Personal data (GDPR)**: Much broader — any information relating to an *identifiable* person:
- IP addresses (Court of Justice of the EU, C-582/14 — *Breyer*)
- Cookie IDs / device fingerprints
- Behavioral/clickstream data linked to a user profile
- Pseudonymized data (if re-identification is possible)
- Location data (even coarse, if it can single someone out)
- Online identifiers under Art. 4(1): "location data, online identifier or to one or more factors specific to the physical, physiological, genetic, mental, economic, cultural or social identity"

**Practical impact**: US companies often scope privacy programs around PII and miss GDPR obligations for IP logs, analytics cookies, and behavioral profiles.

---

## 2. GDPR Deep Dive

### Territorial Scope — Art. 3

The GDPR applies to:
1. **Establishment principle**: Any processing by an organization established in the EU/EEA, regardless of where processing occurs.
2. **Targeting principle**: Any processing of EU residents' data by a non-EU organization when:
   - Offering goods/services to EU residents (even free), **OR**
   - Monitoring behavior of EU residents (e.g., behavioral advertising, web analytics).

> Example: A US SaaS company with no EU office that sells subscriptions to EU customers is fully subject to GDPR.

**DPO requirement triggers** (Art. 37):
- Public authority or body
- Core activities require large-scale systematic monitoring of data subjects
- Core activities involve large-scale processing of special category or criminal data

---

### Six Lawful Bases — Art. 6

| Basis | Condition | Common Use | Notes |
|-------|-----------|-----------|-------|
| **Consent** (6(1)(a)) | Freely given, specific, informed, unambiguous affirmative action | Marketing, analytics cookies, newsletters | Must be withdrawable; no pre-ticked boxes |
| **Contract** (6(1)(b)) | Processing necessary for contract performance or pre-contractual steps | Order fulfilment, account creation | Must be *necessary*, not merely convenient |
| **Legal obligation** (6(1)(c)) | Processing necessary for compliance with EU/member state law | Tax records, AML/KYC | Doesn't cover contractual obligations |
| **Vital interests** (6(1)(d)) | Necessary to protect someone's life | Emergency medical situations | Last resort — not for commercial use |
| **Public task** (6(1)(e)) | Exercise of official authority or public interest task | Government agencies, research | Requires basis in EU/member state law |
| **Legitimate interests** (6(1)(f)) | Necessary for controller's or third party's legitimate interests, unless overridden by data subject's interests/rights | Fraud prevention, security, direct marketing (to existing customers) | Requires LIA (Legitimate Interest Assessment) |

**Legitimate Interest Assessment (LIA) three-part test**:
1. **Purpose test**: Is the interest legitimate?
2. **Necessity test**: Is processing necessary and proportionate?
3. **Balancing test**: Do data subject's interests override the legitimate interest?

---

### Eight Data Subject Rights

| Right | Article | Technical Implementation Required |
|-------|---------|----------------------------------|
| **Right of Access** | Art. 15 | Data export API; search across all data stores by subject ID; 30-day response deadline |
| **Right to Rectification** | Art. 16 | Allow subjects to correct inaccurate data; propagate corrections to downstream systems |
| **Right to Erasure (Right to be Forgotten)** | Art. 17 | Deletion + anonymization pipeline; cascade across backups, logs, caches, third-party processors; exceptions: legal obligation, public interest, legal claims |
| **Right to Restriction of Processing** | Art. 18 | Flag records as "restricted"; cease processing but retain data; notify before restriction is lifted |
| **Right to Data Portability** | Art. 20 | Machine-readable export (JSON/CSV) of data provided by subject or observed through their activity; applies to consent/contract bases only |
| **Right to Object** | Art. 21 | Opt-out mechanism for legitimate interest processing; absolute right to object to direct marketing; suppress from processing pipelines |
| **Rights re Automated Decision-Making** | Art. 22 | Human review pathway for solely automated decisions with significant effect; document logic; allow contestation |
| **Right to Withdraw Consent** | Art. 7(3) | Withdraw must be as easy as giving consent; cease processing on withdrawal; no detriment to subject |

**DSAR (Data Subject Access Request) workflow**:
```
Subject submits DSAR → identity verification → 30-day clock starts
→ search all systems (DB, logs, backups, third parties)
→ compile report → redact third-party data → deliver
→ log completion (for accountability, Art. 5(2))
```

---

### Breach Notification — Arts. 33 & 34

| Requirement | Article | Deadline | Recipient | Threshold |
|-------------|---------|----------|-----------|-----------|
| Notify supervisory authority | Art. 33 | 72 hours from awareness | Lead DPA (e.g., ICO, CNIL, BfDI) | All breaches unless "unlikely to result in risk" |
| Notify data subjects | Art. 34 | "Without undue delay" | Affected individuals | Only when breach likely results in **high risk** to their rights/freedoms |

**Art. 33 notification must include**:
- Nature of breach + categories/approximate number of records affected
- DPO contact details
- Likely consequences
- Measures taken or proposed

**High-risk indicators for Art. 34 notification**: health data, financial data, children's data, data enabling identity theft, large scale, systematic combination of data sets.

---

### GDPR Fines — Art. 83

| Tier | Maximum Fine | Example Violations |
|------|--------------|--------------------|
| **Tier 1** | €10M or 2% global annual turnover (whichever higher) | Processor obligations, DPIA, DPO, certification bodies |
| **Tier 2** | €20M or 4% global annual turnover (whichever higher) | Basic processing principles (Art. 5), lawful basis (Art. 6), consent (Art. 7), data subject rights, international transfers |

**Notable fines**: Meta (€1.2B, 2023 — transfers); Amazon (€746M, 2021 — consent); WhatsApp (€225M, 2021 — transparency).

---

### DPIA — Art. 35

**When mandatory** (Art. 35(3) + EDPB guidelines):
- Systematic and extensive profiling with legal/significant effects
- Large-scale processing of special categories (Art. 9) or criminal data (Art. 10)
- Systematic monitoring of publicly accessible areas (CCTV at scale)
- Also: new technologies, high risk indicated by supervisory authority lists

**DPIA Template Sections**:
1. Description of processing and its purposes
2. Assessment of necessity and proportionality
3. Identification of risks to data subjects
4. Measures to address risks (controls)
5. Consultation with DPO
6. Consultation with data subjects (if appropriate)
7. Sign-off and review date
8. Residual risk acceptance

**Free tool**: CNIL DPIA open-source software — https://www.cnil.fr/en/open-source-pia-software

---

## 3. CCPA / CPRA

### Applicability Thresholds (CCPA + CPRA)

A for-profit business that does business in California and meets **any one** of:
- Annual gross revenues **> $25 million**
- Buys, sells, or shares personal information of **≥ 100,000** consumers or households (CPRA raised from 50K)
- Derives **≥ 50%** of annual revenues from selling or sharing consumers' personal information

---

### Consumer Rights

| Right | Law | Technical Requirement |
|-------|-----|----------------------|
| **Right to Know** | CCPA | Disclose categories and specific pieces of PI collected; respond within 45 days |
| **Right to Delete** | CCPA | Delete PI and direct service providers to delete; exceptions: complete transaction, security, legal obligation |
| **Right to Opt-Out of Sale/Sharing** | CCPA | "Do Not Sell or Share My Personal Information" link on homepage; honor Global Privacy Control (GPC) signal |
| **Right to Non-Discrimination** | CCPA | Cannot deny service, charge different price, or provide lower quality for exercising rights |
| **Right to Correct** | CPRA | Correct inaccurate personal information; 45-day response |
| **Right to Limit Use of Sensitive PI** | CPRA | "Limit the Use of My Sensitive Personal Information" link; restrict to necessary uses |
| **Right to Know about Automated Decision-Making** | CPRA | Disclose use of ADM; right to opt-out (CPPA rulemaking pending) |

---

### Technical Requirements

**Global Privacy Control (GPC)**:
- Browser/extension signal (HTTP header `Sec-GPC: 1` or JS `navigator.globalPrivacyControl === true`)
- Must be honored as opt-out of sale/sharing for California consumers
- CCPA enforcement: Sephora settlement (2022) — $1.2M fine for not honoring GPC

**"Do Not Sell or Share My Personal Information" link**:
- Required on homepage and wherever PI is collected
- Must link to an opt-out mechanism that works without account creation

**Service Provider vs Third Party**:
- **Service provider**: processes PI solely for business purposes under contract — not a "sale"
- **Third party**: receives PI for own purposes — may be a "sale" even if no money changes hands

**Sensitive personal information** (CPRA, heightened protection):
SSN, financial account + credentials, precise geolocation, racial/ethnic origin, religious beliefs, biometric/genetic data, health, sexual orientation, contents of communications.

**CPPA** (California Privacy Protection Agency): Independent enforcement body created by CPRA, can impose fines up to $2,500 per unintentional violation, $7,500 per intentional violation of children's data.

---

## 4. Global Privacy Regulations

| Regulation | Jurisdiction | Effective | Key Requirements |
|------------|-------------|-----------|-----------------|
| **GDPR** | EU / EEA | May 2018 | Lawful basis, 8 subject rights, 72h breach notice, DPIA, DPO, international transfer controls, €20M/4% fines |
| **UK GDPR + DPA 2018** | United Kingdom | Jan 2021 (post-Brexit) | Mirrors GDPR; ICO as supervisory authority; adequacy decision from EU (adopted June 2021, under review) |
| **CCPA / CPRA** | California, USA | Jan 2020 / Jan 2023 | Opt-out of sale/sharing, GPC, right to correct (CPRA), CPPA enforcement |
| **PIPEDA** | Canada (federal) | 2000, updated 2015 | 10 fair information principles; breach notification mandatory since 2018; CPPA (Bill C-27) to modernize |
| **LGPD** | Brazil | Aug 2020 | Based on GDPR; 10 lawful bases; ANPD as authority; fines up to 2% Brazil annual revenue (max R$50M per violation) |
| **APPI** | Japan | 2003, major revisions 2022 | Opt-in consent for sensitive data; 3rd party transfer restrictions; breach notification to PPC and subjects; PPC as authority |
| **PDPA (Thailand)** | Thailand | Jun 2022 | GDPR-inspired; consent-first; PDPC as authority; fines up to THB 5M criminal + THB 3M administrative |
| **PDPA (Singapore)** | Singapore | Jul 2014, amended 2021 | Consent, purpose limitation, data breach notification (mandatory since 2021); PDPC; fines up to S$1M |
| **HIPAA** | US healthcare | 1996, updated 2013 (Omnibus) | PHI protection; Privacy Rule + Security Rule; BAAs with vendors; breach notification to HHS + patients; fines up to $1.9M/category/year |
| **GLBA (GLB Act)** | US financial | 1999 | Safeguards Rule (FTC); require financial institutions to protect NPI; written security plan; vendor oversight |
| **FERPA** | US education | 1974 | Protect student education records; parental rights until age 18; restrict disclosure without consent; no fines but loss of federal funding |
| **COPPA** | US children online | 1998, updated 2013 | Verifiable parental consent for under-13 data collection; no behavioral advertising to children; FTC enforcement; up to $51,744/violation |
| **China PIPL** | China | Nov 2021 | GDPR-like rights; data localization for critical infrastructure; cross-border transfer restrictions (CAC approval or SCCs); fines up to ¥50M or 5% revenue |
| **ePrivacy Directive** | EU | 2002, updated 2009 | Cookie consent (requires GDPR-level consent); confidentiality of communications; transposed into national law; ePrivacy Regulation pending |

---

## 5. Privacy by Design — 7 Principles

Ann Cavoukian's Privacy by Design (PbD) — developed in the 1990s, codified in GDPR Recital 78 and Art. 25 (data protection by design and by default).

### The 7 Foundational Principles

#### Principle 1: Proactive not Reactive; Preventive not Remedial
- Anticipate and prevent privacy-invasive events before they occur
- **Software application**: Privacy threat modeling (LINDDUN) at design phase; privacy user stories in sprint planning ("As a user I want my search history deleted when I close a session"); privacy gate in SDLC before production deploy

#### Principle 2: Privacy as the Default Setting
- Maximum privacy protection is the default — no action required from the user to protect their privacy
- **Software application**: Opt-in analytics (not opt-out); minimal data collection by default; shortest retention by default; private profile visibility by default; disable tracking cookies unless explicitly enabled

#### Principle 3: Privacy Embedded into Design
- Privacy is integral to the system architecture, not an add-on
- **Software application**: Data minimization in schema design (don't add fields "just in case"); purpose limitation enforced at code level (tag data use); privacy-aware data models; no PII in log files by design

#### Principle 4: Full Functionality — Positive-Sum, not Zero-Sum
- Privacy AND security AND functionality — all achieved simultaneously; avoid false trade-offs
- **Software application**: End-to-end encryption that still allows business analytics (aggregate/anonymized); privacy-preserving ML (federated learning, differential privacy); pseudonymization that retains analytical utility

#### Principle 5: End-to-End Security — Full Lifecycle Protection
- Strong security throughout the entire data lifecycle: collection → processing → storage → sharing → deletion
- **Software application**: Encryption at rest and in transit; key management (HSM/KMS); secure deletion (crypto-shredding); data retention automation; processor contracts; backup encryption

#### Principle 6: Visibility and Transparency
- Keep it open — independent verification of practices; honest privacy notices; accountability
- **Software application**: Clear, layered privacy notices; consent audit logs; ROPA maintained; privacy dashboards for users; third-party sub-processor lists published

#### Principle 7: Respect for User Privacy — Keep it User-Centric
- Protect users' interests above all; strong privacy defaults; clear notices; user-friendly options; user empowerment
- **Software application**: Self-service privacy dashboards; DSAR portals; preference centres; just-in-time notices; plain-language privacy policies

---

### PbD in Software Development

**Privacy User Stories** (examples):
- "As a user, I want to export all my data in JSON format so I can exercise my portability right"
- "As a user, I want to delete my account and have all my personal data removed within 30 days"
- "As a developer, I do not want PII to appear in application logs so that we comply with data minimization"

**LINDDUN Privacy Threat Model**:

| Threat | Description | Example |
|--------|-------------|---------|
| **L**inkability | Link items without knowing identity | Cross-site tracking via fingerprint |
| **I**dentifiability | Identify a data subject | Re-identification from "anonymized" dataset |
| **N**on-repudiation | Subject cannot deny action | Immutable audit log records all user actions |
| **D**etectability | Detect that data/communication exists | Traffic analysis reveals communication patterns |
| **D**isclosure of information | Learn content of data | Unencrypted PII in transit |
| **U**nawareness | Subject unaware of processing | Hidden tracking pixels |
| **N**on-compliance | Violates regulation/policy | No consent for analytics cookies |

**Data Minimization in API Design**:
```python
# BAD: Returns entire user object including PII
def get_user_for_display(user_id):
    return User.objects.get(id=user_id)  # Returns DOB, SSN, address, etc.

# GOOD: Return only fields needed for this specific purpose
def get_user_for_display(user_id):
    return User.objects.filter(id=user_id).values('id', 'username', 'display_name')
```

**Purpose Limitation Tagging**:
```python
# Tag data use at collection point
@data_purpose(purposes=["order_fulfilment", "fraud_prevention"])
def collect_shipping_address(user_id, address):
    # This data must not be used for marketing without separate consent
    pass
```

---

## 6. Data Classification & Records of Processing Activity (ROPA)

### Data Classification Tiers

| Tier | Examples | Controls Required |
|------|---------|------------------|
| **Public** | Press releases, public docs, open-source code | No special controls; verify intentional publication |
| **Internal** | Internal policies, org charts, general business comms | Access control; no external sharing without approval |
| **Confidential** | Customer data (non-sensitive), financial reports, IP, contracts | Encryption at rest + transit; need-to-know access; DLP monitoring; NDA for third parties |
| **Restricted / Sensitive** | Health data (PHI), payment data (PAN), government IDs, biometrics, credentials, trade secrets | Strongest encryption (AES-256+); MFA required; audit logging all access; tokenization/pseudonymization; strict retention limits; DPIA required before processing |

**Labeling tools**: Microsoft Purview Information Protection, Google Cloud DLP, Varonis, Boldon James.

---

### ROPA — Art. 30 Required Fields

Organizations with ≥ 250 employees (or processing high-risk/regular/sensitive data) must maintain a Record of Processing Activities.

**Controller ROPA required fields** (Art. 30(1)):
1. Name and contact of controller (and DPO if applicable)
2. **Purposes** of processing
3. **Categories** of data subjects and personal data
4. **Recipients** (including third countries/international orgs)
5. **Transfers** to third countries + safeguards
6. **Retention** periods (or criteria)
7. **Security measures** (technical and organisational, where possible)

**Sample ROPA Entry — Customer Order Processing**:
```python
ROPA_ENTRY = {
    "process_id": "PROC-001",
    "process_name": "Customer Order Processing",
    "controller": "Acme Corp, privacy@acme.com",
    "dpo": "Jane Smith, dpo@acme.com",
    "purposes": [
        "Fulfilment of purchase contract (Art. 6(1)(b))",
        "Legal obligation — VAT records (Art. 6(1)(c))"
    ],
    "data_subjects": ["customers", "prospective_customers"],
    "data_categories": [
        "name", "email", "delivery_address", "payment_method_token",
        "order_history", "IP_address"
    ],
    "recipients": [
        {"name": "Stripe", "role": "processor", "purpose": "payment_processing", "country": "US", "safeguard": "SCCs + DPF"},
        {"name": "FedEx", "role": "processor", "purpose": "delivery", "country": "US", "safeguard": "SCCs"},
        {"name": "AWS", "role": "processor", "purpose": "hosting", "country": "US", "safeguard": "SCCs + BCRs"}
    ],
    "retention": {
        "order_data": "7 years (legal obligation — tax)",
        "marketing_preferences": "Until consent withdrawn or 3 years inactivity",
        "server_logs": "90 days"
    },
    "security_measures": [
        "AES-256 encryption at rest",
        "TLS 1.3 in transit",
        "PAN tokenized (never stored)",
        "Access control — role-based, least privilege",
        "Annual penetration testing"
    ],
    "dpia_required": False,
    "dpia_reference": None,
    "last_reviewed": "2025-01-15"
}
```

---

## 7. Technical Privacy Controls

### Pseudonymization — Art. 4(5)

Pseudonymization replaces directly identifying data with an artificial identifier. The mapping is stored separately. The data is **still personal data** — GDPR still applies, but with reduced risk (affects DPIA risk scoring, breach impact assessment).

**HMAC-Based Deterministic Pseudonymization** (Python):
```python
import hmac
import hashlib
import secrets

# Secret key — stored in HSM or secrets manager, never in code
PSEUDONYM_SECRET = secrets.token_bytes(32)

def pseudonymize(value: str, domain: str = "default") -> str:
    # Deterministic pseudonymization using HMAC-SHA256.
    # Same input + same key = same output (enables joining tables).
    # Different domain = different pseudonym for same value (domain separation).
    msg = f"{domain}:{value}".encode("utf-8")
    return hmac.new(PSEUDONYM_SECRET, msg, hashlib.sha256).hexdigest()

# Example usage
email_pseudo = pseudonymize("user@example.com", domain="email")
# Same call always returns same pseudonym — linkable within system
# But without PSEUDONYM_SECRET, cannot reverse

# Re-pseudonymization: rotate the key to break old pseudonyms
def re_pseudonymize(old_pseudonym: str, old_key: bytes, new_key: bytes, domain: str) -> str:
    raise NotImplementedError("Re-pseudonymization requires original values — use key rotation at source")
```

**Key management for pseudonymization**:
- Store key in HSM (Hardware Security Module) or cloud KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS)
- Separate key per domain (email, phone, SSN) — domain separation prevents cross-domain linkage
- Key rotation schedule: annually minimum; immediately on suspected compromise
- Access controls: only the pseudonymization service can access the key; no developer access

---

### Anonymization Techniques

True anonymization makes re-identification impossible — the data is no longer personal data and falls outside GDPR scope. In practice, anonymization is very difficult.

#### k-Anonymity
A dataset satisfies k-anonymity if every record is indistinguishable from at least k-1 other records with respect to quasi-identifiers (age, ZIP code, gender).

```
k=3 example (ZIP, Age, Gender):
10001, 28, M  →  10001, 2*, M   (generalized)
10001, 29, M  →  10001, 2*, M
10001, 27, M  →  10001, 2*, M
Each row now matches at least 2 others — k=3 satisfied
```

**Weakness**: Homogeneity attack (if all k records share the same sensitive attribute, knowing quasi-identifiers reveals it).

#### l-Diversity
Extension of k-anonymity — each equivalence class must have at least l "well-represented" values for the sensitive attribute.

#### t-Closeness
Distribution of sensitive attribute in each group must be close to its distribution in the whole dataset (distance ≤ t).

#### Differential Privacy
Provides mathematical privacy guarantee: output of a query changes by at most a factor of e^ε when any single record is added/removed.

```python
# Using Google's PyDP library (wrapper for Google's DP library)
# pip install python-dp

import pydp as dp
from pydp.algorithms.laplacian import BoundedMean

# epsilon=1.0: privacy budget (lower = more private, less accurate)
# lower_bound/upper_bound: clamp values to limit sensitivity
dp_mean = BoundedMean(epsilon=1.0, lower_bound=18, upper_bound=100, dtype="float")

ages = [25, 34, 45, 29, 52, 38, 61, 27]  # User ages — sensitive
private_mean_age = dp_mean.quick_result(ages)
print(f"DP mean age: {private_mean_age:.1f}")  # Noisy but private result
```

**Choosing epsilon**: ε=0.1 (strong privacy), ε=1.0 (typical research use), ε=10 (high utility, weaker privacy). Apple uses ε=8 for iOS usage statistics.

---

### Data Tokenization

Replaces sensitive PII/payment data with a non-sensitive token. Token vault maps tokens to actual values; token itself has no exploitable value.

**Tokenization vs Encryption**:
| Aspect | Tokenization | Encryption |
|--------|-------------|-----------|
| Output | Random token (no mathematical relation to input) | Ciphertext (mathematical transformation) |
| Reversibility | Via vault lookup only | Via decryption with key |
| Length preservation | Format-preserving options available | Usually different length |
| Key compromise | Vault breach required | Key compromise = all data exposed |

**Use cases**:
- **PCI DSS**: Tokenize Primary Account Number (PAN); application uses token; only token vault touches real card number
- **HIPAA**: Tokenize patient identifiers; analytics systems work with tokens
- **Internal**: Tokenize SSNs, passport numbers in non-payment systems

**Providers**:
- **Tokenex**: Cloud tokenization platform; format-preserving tokens; PCI-validated
- **Bluefin**: P2PE (Point-to-Point Encryption) + tokenization for payments
- **AWS Payment Cryptography**: Managed token vault; integrates with AWS services
- **Protegrity**: Enterprise data security platform; field-level tokenization

**Architecture**:
```
Application → Token Request → Token Vault (HSM-backed) → Token returned
Application stores token → Token Vault stores real value encrypted with HSM key
Detokenize only for authorized services (e.g., payment processor) → audit logged
```

---

### Field-Level Encryption

Encrypt specific sensitive fields at the application level — database stores ciphertext.

```python
from cryptography.fernet import Fernet
import base64

# Key generation — store in KMS/HSM, not in code
key = Fernet.generate_key()
f = Fernet(key)

# Encrypt a sensitive field
plaintext_email = b"user@example.com"
encrypted_email = f.encrypt(plaintext_email)
# encrypted_email is safe to store in database

# Decrypt when needed (access-controlled)
decrypted_email = f.decrypt(encrypted_email)
assert decrypted_email == plaintext_email

# Django model example with encrypted field
class UserProfile(models.Model):
    username = models.CharField(max_length=150)  # Non-sensitive
    encrypted_email = models.BinaryField()       # Stored encrypted
    encrypted_ssn = models.BinaryField()         # Stored encrypted

    def set_email(self, email: str):
        self.encrypted_email = f.encrypt(email.encode())

    def get_email(self) -> str:
        return f.decrypt(bytes(self.encrypted_email)).decode()
```

**Libraries**: `cryptography` (Python Fernet/AES-GCM), `django-encrypted-model-fields`, `sqlalchemy-utils` EncryptedType, `pgcrypto` (PostgreSQL native).

**Key rotation**: Re-encrypt all rows with new key; use envelope encryption (data key encrypted with master key in KMS — rotate master key without re-encrypting all data).

---

### Consent Management

#### CMP Tools

| Tool | Use Case | TCF Support |
|------|---------|-------------|
| **OneTrust** | Enterprise; full privacy program; DSAR portal + consent | Yes (IAB TCF 2.2) |
| **Cookiebot (Usercentrics)** | SMB/mid-market; auto-scan cookies; geolocation-based consent | Yes |
| **Usercentrics** | Enterprise; A/B testing consent UX; granular consent | Yes |
| **Osano** | US-focused; GPC support; simple integration | Partial |
| **Sourcepoint** | Publishing/media; TCF + US state law compliance | Yes |

#### Required Consent Record Fields

Every consent event must be logged with:
```python
CONSENT_RECORD = {
    "consent_id": "uuid4",
    "user_id": "pseudonymized_user_id",     # Not plaintext email
    "timestamp_utc": "2025-06-15T14:32:01Z",
    "ip_address": "hashed_or_truncated",    # Don't store full IP if avoidable
    "user_agent": "Mozilla/5.0...",
    "purposes_consented": [1, 2, 3],        # IAB TCF purpose IDs or custom purpose codes
    "purposes_declined": [4, 5],
    "consent_string": "IAB_TCF_v2_string",  # Full TCF consent string
    "notice_version": "privacy-policy-2025-06-01",
    "consent_method": "explicit_click",     # explicit_click | scroll | implied (last is invalid for GDPR)
    "withdrawal_timestamp": None,           # Set when consent withdrawn
    "legal_jurisdiction": "EU"
}
```

#### IAB TCF 2.2 JavaScript Integration

```javascript
// Check TCF 2.2 consent before firing analytics
window.__tcfapi('getTCData', 2, function(tcData, success) {
    if (success && tcData.gdprApplies) {
        // Purpose 1 = Store and/or access information on a device (cookies)
        // Purpose 7 = Use profiles for personalised advertising
        const cookieConsent = tcData.purpose.consents[1];
        const analyticsConsent = tcData.purpose.consents[7];

        if (cookieConsent) {
            // Fire analytics
            gtag('config', 'GA-XXXXXXXX');
        }
        if (!analyticsConsent) {
            // Block advertising pixels
            blockAdvertisingPixels();
        }
    } else if (!tcData.gdprApplies) {
        // GDPR does not apply (non-EU user) — still check CCPA/GPC
        if (!navigator.globalPrivacyControl) {
            gtag('config', 'GA-XXXXXXXX');
        }
    }
});
```

---

### PII Detection with Regex (Python)

```python
import re
from typing import Dict

# PII detection patterns
PII_PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        re.IGNORECASE
    ),
    "us_ssn": re.compile(
        r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
    ),
    "credit_card": re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?'          # Visa
        r'|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}'  # Mastercard
        r'|3[47][0-9]{13}'                          # Amex
        r')\b'
    ),
    "uk_nino": re.compile(
        r'\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b',
        re.IGNORECASE
    ),
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    "us_phone": re.compile(
        r'\b(?:\+1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)[0-9]{3}[-.\s]?[0-9]{4}\b'
    ),
}

def scan_for_pii(text: str) -> Dict[str, int]:
    # Scan text for PII patterns.
    # Returns dict of {pii_type: count_of_matches}.
    results: Dict[str, int] = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            results[pii_type] = len(matches)
    return results

def redact_pii(text: str) -> str:
    # Replace detected PII with redaction markers.
    redacted = text
    for pii_type, pattern in PII_PATTERNS.items():
        redacted = pattern.sub(f"[REDACTED_{pii_type.upper()}]", redacted)
    return redacted

# Example
sample_log = "User john@example.com (SSN: 123-45-6789) from 192.168.1.1 placed order"
findings = scan_for_pii(sample_log)
print(findings)  # {'email': 1, 'us_ssn': 1, 'ipv4': 1}
print(redact_pii(sample_log))
# "User [REDACTED_EMAIL] (SSN: [REDACTED_US_SSN]) from [REDACTED_IPV4] placed order"
```

---

### DLP (Data Loss Prevention)

**Network DLP**:
- Inspect outbound traffic (email, HTTP/S, FTP) for PII patterns
- Tools: Symantec DLP (Broadcom), Forcepoint DLP, GTB Technologies
- Deployment: Inline proxy (block) or out-of-band (alert)
- HTTPS inspection requires SSL intercept — creates its own privacy considerations

**Endpoint DLP**:
- Block USB drive copy of sensitive files
- Screenshot/screen-capture restrictions for sensitive applications
- Clipboard monitoring — prevent copy-paste of PII to non-approved apps
- Tools: Microsoft Purview Endpoint DLP, CrowdStrike Falcon DLP, Digital Guardian

**Cloud DLP**:
- **Google Cloud DLP**: Scan Cloud Storage, BigQuery, Datastore for 150+ predefined infoTypes; de-identify (redact, mask, tokenize, pseudonymize) in pipeline; API for custom scanning
- **Microsoft Purview**: Unified DLP across M365, Teams, SharePoint, Exchange, Endpoint; sensitivity labels
- **AWS Macie**: ML-powered PII discovery in S3; sensitive data findings

**CASB (Cloud Access Security Broker)**:
- Monitor and control SaaS application usage
- Detect unauthorized file sharing (e.g., Google Drive shared externally)
- DLP policies for SaaS: block upload of files containing SSNs to personal Dropbox
- Tools: Microsoft Defender for Cloud Apps, Netskope, Zscaler CASB

---

## 8. Privacy Engineering in APIs

### Data Minimization

Return only the fields required for the stated purpose — projection at the database query level.

```python
# BAD: Returns full User object including DOB, address, SSN, phone
class UserDetailView(APIView):
    def get(self, request, user_id):
        user = User.objects.get(id=user_id)
        return Response(UserSerializer(user).data)  # Exposes all fields

# GOOD: Return only display-safe fields for this specific use case
class UserProfileView(APIView):
    def get(self, request, user_id):
        user = User.objects.filter(id=user_id).values(
            'id', 'username', 'display_name', 'avatar_url'
        ).first()
        return Response(user)
```

### Purpose Limitation Enforcement

```python
# Decorator to enforce data purpose at API layer
from functools import wraps
from enum import Enum

class DataPurpose(Enum):
    ORDER_FULFILMENT = "order_fulfilment"
    FRAUD_PREVENTION = "fraud_prevention"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    SUPPORT = "support"

def require_purpose(allowed_purposes: list):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            request_purpose = request.headers.get("X-Data-Purpose")
            if request_purpose not in [p.value for p in allowed_purposes]:
                return HttpResponse(status=403,
                    content="Purpose not authorized for this endpoint")
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

@require_purpose([DataPurpose.ORDER_FULFILMENT, DataPurpose.FRAUD_PREVENTION])
def get_shipping_address(request, user_id):
    # Only accessible for order/fraud purposes, not marketing
    pass
```

### Privacy Audit Logging

```python
import uuid
from datetime import datetime, timezone

def log_data_access(
    accessor_id: str,
    accessor_type: str,          # "user" | "service" | "admin"
    data_subject_id: str,        # Pseudonymized subject identifier
    fields_accessed: list,       # ["email", "dob"] — what fields were accessed
    purpose: str,                # DataPurpose enum value
    legal_basis: str,            # "contract" | "consent" | "legal_obligation" etc.
    request_ip: str,
    outcome: str = "success"
):
    # Log all access to personal data for accountability (GDPR Art. 5(2)).
    log_entry = {
        "log_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "accessor_id": accessor_id,
        "accessor_type": accessor_type,
        "data_subject_id": data_subject_id,
        "fields_accessed": fields_accessed,
        "purpose": purpose,
        "legal_basis": legal_basis,
        "request_ip": request_ip,  # Consider hashing/truncating for GDPR
        "outcome": outcome
    }
    # Write to append-only audit log store (not deletable by application)
    AuditLog.objects.create(**log_entry)
```

### Retention Enforcement — Automated Deletion

```python
# Django management command for automated data retention enforcement
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Enforce data retention policies — delete or anonymize expired records'

    RETENTION_POLICIES = {
        'Order': {'field': 'created_at', 'days': 7 * 365, 'action': 'retain'},   # 7yr legal
        'UserSession': {'field': 'created_at', 'days': 90, 'action': 'delete'},
        'MarketingProfile': {'field': 'last_consent_at', 'days': 3 * 365, 'action': 'anonymize'},
        'ServerLog': {'field': 'timestamp', 'days': 90, 'action': 'delete'},
        'InactiveUser': {'field': 'last_login', 'days': 3 * 365, 'action': 'anonymize'},
    }

    def handle(self, *args, **options):
        for model_name, policy in self.RETENTION_POLICIES.items():
            cutoff = timezone.now() - timedelta(days=policy['days'])
            model = apps.get_model(app_label='myapp', model_name=model_name)
            expired_qs = model.objects.filter(**{f"{policy['field']}__lt": cutoff})

            if policy['action'] == 'delete':
                count, _ = expired_qs.delete()
                self.stdout.write(f"Deleted {count} expired {model_name} records")
            elif policy['action'] == 'anonymize':
                count = expired_qs.update(
                    email="anon@deleted.invalid",
                    name="[Deleted User]",
                    phone="",
                    ip_address="0.0.0.0"
                )
                self.stdout.write(f"Anonymized {count} expired {model_name} records")
```

---

## 9. Privacy Impact Assessment (PIA / DPIA)

### When a DPIA is Required — Art. 35

**Mandatory triggers** (EDPB Guidelines 09/2022 + Art. 35(3)):
- Processing likely to result in high risk — assess if 2+ criteria below are met:
  1. Evaluation or scoring (profiling)
  2. Automated decision-making with legal/significant effects
  3. Systematic monitoring (CCTV, employee monitoring, network monitoring)
  4. Sensitive data or highly personal data (Art. 9/10 + location, financial, behavioral)
  5. Large-scale processing
  6. Matching or combining datasets from different sources
  7. Vulnerable data subjects (children, patients, employees)
  8. Innovative use of technology (IoT, AI, facial recognition)
  9. Data transfers outside EU without adequate protection
  10. Processing that prevents exercise of rights or use of services

### DPIA Template — 8 Sections

| Section | Content |
|---------|---------|
| **1. Processing Description** | Purpose, legal basis, data categories, data subjects, volumes, retention, recipients, third countries |
| **2. Necessity & Proportionality** | Is processing necessary for the stated purpose? Is there a less privacy-intrusive alternative? |
| **3. Risk Identification** | Identify threats to confidentiality, integrity, availability; identify privacy harms to data subjects |
| **4. Risk Assessment** | Likelihood (1-5) × Severity (1-5) = Risk score (1-25); categorise residual risks |
| **5. Controls & Mitigations** | Technical and organisational measures for each identified risk; control owner |
| **6. DPO Consultation** | DPO advice and recommendations; date of consultation |
| **7. Data Subject Consultation** | Consultation with affected individuals or their representatives (where appropriate) |
| **8. Approval & Review** | Risk owner acceptance; DPO sign-off; next review date (trigger: change in processing or annually) |

### Risk Matrix

| | **Severity 1** (Minimal) | **Severity 2** (Limited) | **Severity 3** (Significant) | **Severity 4** (High) | **Severity 5** (Maximum) |
|-|--------------------------|--------------------------|------------------------------|-----------------------|--------------------------|
| **Likelihood 5** (Near certain) | 5 — Low | 10 — Medium | 15 — High | 20 — Very High | 25 — Critical |
| **Likelihood 4** (Likely) | 4 — Low | 8 — Medium | 12 — High | 16 — Very High | 20 — Very High |
| **Likelihood 3** (Possible) | 3 — Low | 6 — Medium | 9 — Medium | 12 — High | 15 — High |
| **Likelihood 2** (Unlikely) | 2 — Low | 4 — Low | 6 — Medium | 8 — Medium | 10 — Medium |
| **Likelihood 1** (Rare) | 1 — Low | 2 — Low | 3 — Low | 4 — Low | 5 — Low |

**Risk thresholds**: 1-5 = Accept, 6-9 = Monitor, 10-15 = Treat (implement controls), 16-25 = Escalate/consult DPA.

**CNIL DPIA Free Software**: https://www.cnil.fr/en/open-source-pia-software
GitHub: https://github.com/LINCnil/pia

---

## 10. International Data Transfers

### GDPR Transfer Mechanisms — Arts. 45-49

| Mechanism | Legal Basis | Notes |
|-----------|------------|-------|
| **Adequacy Decision** (Art. 45) | EU Commission declares third country has equivalent protection | Countries: UK (under review), Canada (partial), Japan, New Zealand, Switzerland, Israel, South Korea (limited), US (DPF certified companies only) |
| **Standard Contractual Clauses (SCCs)** (Art. 46(2)(c)) | Contract between exporter and importer with standard EU Commission clauses | New 2021 SCCs mandatory since Dec 2022; four modules (C2C, C2P, P2P, P2C); must conduct Transfer Impact Assessment (TIA) |
| **Binding Corporate Rules (BCRs)** (Art. 47) | Intra-group transfers for multinationals; approved by lead DPA | Expensive/time-consuming; approved BCR covers all group entities |
| **Consent** (Art. 49(1)(a)) | Explicit, informed consent to the specific transfer | Not suitable for systematic transfers; one-time/occasional only |
| **Contract necessity** (Art. 49(1)(b)) | Transfer necessary for contract performance (e.g., book hotel abroad) | Occasional use only |
| **Legitimate interests** (Art. 49(1)(g)) | Compelling legitimate interests; not repetitive; inform DPA | Rarely applicable |

### Schrems II Impact (C-311/18, July 2020)

- EU-US **Privacy Shield invalidated** — not adequate protection due to US surveillance laws (FISA 702, EO 12333)
- SCCs remain valid **BUT** exporters must conduct Transfer Impact Assessment (TIA) to verify effective protection
- **Supplementary measures** (TIA-triggered): encryption with keys in EU only; pseudonymization; no transfer of sensitive data; contractual redress mechanisms

### EU-US Data Privacy Framework (DPF) — July 2023

- New adequacy decision for transfers to DPF-certified US organizations
- Stronger safeguards: US Executive Order 14086 — proportionality/necessity requirements for US intelligence; Data Protection Review Court for EU complaints
- Participation: US companies self-certify to Dept. of Commerce; list at https://www.dataprivacyframework.gov
- **Schrems III risk**: Privacy activists already challenged in EU courts; companies should maintain SCC fallback

### Data Localization Requirements

| Country | Law | Requirement |
|---------|-----|-------------|
| **China** | PIPL (2021) + CSL (2017) | Critical information infrastructure operators must store personal data in China; cross-border transfers require CAC security assessment (>1M people), standard contract, or certification |
| **Russia** | FZ-152 (amended 2014) | Personal data of Russian citizens must be stored on servers located in Russia; Roskomnadzor enforcement (fined LinkedIn 2016) |
| **India** | DPDP Act (2023) | Government may notify categories of data that must be stored in India; cross-border transfer restrictions by notification |
| **Indonesia** | GR 71/2019 | Strategic electronic system operators must have domestic data centers; cross-border requires "equivalent protection" |

---

## 11. Privacy Compliance Program

### Key Roles

| Role | Responsibilities | Mandatory Under |
|------|-----------------|----------------|
| **DPO (Data Protection Officer)** | Independent oversight; advise on GDPR compliance; monitor DPIA; cooperate with DPA; be point of contact for data subjects and DPA | GDPR Art. 37 (public authorities, large-scale monitoring, large-scale special category processing) |
| **Privacy Counsel** | Legal interpretation of privacy laws; draft/review contracts (DPAs, SCCs, BAAs); regulatory response; litigation | Not mandated, but essential for any significant data controller |
| **Privacy Engineer** | Technical implementation of privacy controls; privacy review in SDLC; ROPA technical sections; pseudonymization/encryption implementation; DSAR tooling | Not mandated by name; role emerging in larger orgs |
| **Privacy Champion** | Dev team-embedded advocate; ensure privacy user stories; flag privacy risks in design; attend privacy office briefings | Not mandated; recommended practice for Agile teams |

### Annual Privacy Program Activities

| Activity | Frequency | Owner | Output |
|----------|-----------|-------|--------|
| **Data inventory / ROPA review** | Annual + on change | Privacy Engineer / DPO | Updated ROPA; gap identification |
| **Privacy risk assessment** | Annual | DPO + CISO | Risk register; DPIA queue |
| **Consent audit** | Annual + on notice change | CMP admin | Consent record completeness; renewal needs |
| **Vendor / processor assessment** | Annual (+ on contract) | Procurement + Privacy | DPA coverage; sub-processor list |
| **Privacy training** | Annual (all staff) + role-based | L&D + Privacy | Completion records (accountability) |
| **Policy review** | Annual | Privacy Counsel | Updated privacy notice, internal policy, records |
| **Breach response drill** | Annual | Privacy + Security | Tested 72h notification procedure |
| **DSAR process test** | Annual | Privacy Ops | Tested response workflow; time-to-completion |
| **Third-party pen test** | Annual | CISO | Assurance for security measures under Art. 32 |
| **DPA engagement** | As needed (DPIA consultation, breach notification) | DPO | Maintained regulator relationship |

### Key Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| **DSAR response time** | < 30 days (GDPR) / < 45 days (CCPA) | Track from receipt to delivery; document any extensions |
| **Consent rate** | Baseline + monitor for drops | Sudden drop may indicate CMP/notice issue |
| **Privacy training completion** | > 95% annual | Role-based completion for engineers, marketing, HR |
| **Data inventory completeness** | > 90% of systems mapped | Track systems without ROPA entry |
| **Vendor DPA coverage** | 100% of processors | Any processor without a DPA is a GDPR violation (Art. 28) |
| **DPIA completion rate** | 100% of triggered projects | Track projects in flight vs DPIA complete |
| **Breach notification timeliness** | 100% within 72 hours | Any miss is a regulatory incident |
| **Erasure request fulfilment** | 100% within 30 days | Track propagation to all systems including backups |

---

## Quick Reference: Regulation Applicability Checklist

```
Processing EU residents' data?
  └─ Yes → GDPR applies (regardless of org location)
       ├─ Sensitive data (Art. 9) → need explicit consent or specific exception
       ├─ > 250 employees or high-risk processing → ROPA required
       ├─ High-risk processing → DPIA required
       └─ Transferring outside EU/EEA → need transfer mechanism

US healthcare data (PHI)?
  └─ Yes → HIPAA applies → BAAs with all vendors; breach notification to HHS

US financial data (NPI)?
  └─ Yes → GLBA Safeguards Rule → written security plan; vendor oversight

California users + revenue/data volume threshold?
  └─ Yes → CCPA/CPRA → Do Not Sell link; GPC; 45-day DSAR response

Children under 13 (US)?
  └─ Yes → COPPA → verifiable parental consent

Payment card data?
  └─ Yes → PCI DSS → tokenize PAN; no storage of CVV; annual QSA audit
```

---

*Reference compiled for TeamStarWolf cybersecurity library. Verify regulatory details against primary sources and qualified legal counsel — regulations evolve.*
