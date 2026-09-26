# CWE Weakness Reference

> [MITRE CWE](https://cwe.mitre.org/) (Common Weakness Enumeration) catalogs the **969 software and hardware weakness types** that vulnerabilities (CVEs) are instances of. CWE is the *weakness* node of the [threat-informed knowledge graph](THREAT_INFORMED_DEFENSE_REFERENCE.md) — **CVE → CWE → CAPEC → ATT&CK → D3FEND** — answering *why* an exploit works. See the official [CWE Top 25 Most Dangerous Weaknesses](https://cwe.mitre.org/top25/).

Machine-readable: [`data/weaknesses/cwe.jsonl`](data/weaknesses/cwe.jsonl). Related: [CAPEC Attack Patterns](CAPEC_REFERENCE.md) · [Secure Coding](SECURE_CODING_REFERENCE.md).

| | |
|---|---|
| **Read this when** | a CVE cites a CWE and you need to know what the underlying weakness actually is, you are prioritizing secure-coding or testing work by weakness type, you want to know which weaknesses attackers target most |
| **Start at** | [Most-attacked weaknesses](#most-attacked-weaknesses) for the CAPEC-ranked hit list, [Pillars](#pillars-the-top-level-weakness-categories) for the top-level taxonomy, [Weakness classes](#weakness-classes) for the practical class-level view |

### Abstraction levels

CWE is a hierarchy: **10 Pillars** (most abstract) → **114 Classes** → **539 Base** → **299 Variants** (most specific), plus **7 Compound** weaknesses.

## Pillars — the top-level weakness categories

| CWE | Weakness | Description |
|---|---|---|
| [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Improper Access Control | The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor. |
| [CWE-435](https://cwe.mitre.org/data/definitions/435.html) | Improper Interaction Between Multiple Correctly-Behaving Entities | An interaction error occurs when two entities have correct behavior when running independently of each other, but when they are integrated a |
| [CWE-664](https://cwe.mitre.org/data/definitions/664.html) | Improper Control of a Resource Through its Lifetime | The product does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release. |
| [CWE-682](https://cwe.mitre.org/data/definitions/682.html) | Incorrect Calculation | The product performs a calculation that generates incorrect or unintended results that are later used in security-critical decisions or reso |
| [CWE-691](https://cwe.mitre.org/data/definitions/691.html) | Insufficient Control Flow Management | The code does not sufficiently manage its control flow during execution, creating conditions in which the control flow can be modified in un |
| [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | Protection Mechanism Failure | The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the pr |
| [CWE-697](https://cwe.mitre.org/data/definitions/697.html) | Incorrect Comparison | The product compares two entities in a security-relevant context, but the comparison is incorrect. |
| [CWE-703](https://cwe.mitre.org/data/definitions/703.html) | Improper Check or Handling of Exceptional Conditions | The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product. |
| [CWE-707](https://cwe.mitre.org/data/definitions/707.html) | Improper Neutralization | The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are |
| [CWE-710](https://cwe.mitre.org/data/definitions/710.html) | Improper Adherence to Coding Standards | The product does not follow certain coding rules for development, which can lead to resultant weaknesses or increase the severity of the ass |

---

## Most-attacked weaknesses

Ranked by the number of CAPEC attack patterns that target them — a data-driven view of which weaknesses have the richest known exploit tradecraft.

| CWE | Weakness | Abstraction | CAPEC patterns | Consequences |
|---|---|---|--:|---|
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information to an Unauthorized Actor | Class | 59 | Read Application Data |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | Class | 51 | DoS, Execute Unauthorized Code or Commands, Modify Memory |
| [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | Class | 37 | Alter Execution Logic, Bypass Protection Mechanism, Hide Activities |
| [CWE-697](https://cwe.mitre.org/data/definitions/697.html) | Incorrect Comparison | Pillar | 29 | Varies by Context |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of Resources Without Limits or Throttling | Base | 20 | DoS |
| [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Improper Access Control | Pillar | 17 | Varies by Context |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | Class | 17 | Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity, Modify Application Data |
| [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | Protection Mechanism Failure | Pillar | 17 | Bypass Protection Mechanism |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | Class | 16 | Gain Privileges or Assume Identity, Varies by Context |
| [CWE-707](https://cwe.mitre.org/data/definitions/707.html) | Improper Neutralization | Pillar | 16 | Other |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | Base | 14 | Bypass Protection Mechanism |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Missing Encryption of Sensitive Data | Class | 14 | Modify Application Data, Read Application Data |
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Base | 13 | DoS, Execute Unauthorized Code or Commands, Modify Memory |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | Class | 13 | Gain Privileges or Assume Identity |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | Inclusion of Functionality from Untrusted Control Sphere | Base | 13 | Execute Unauthorized Code or Commands |
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) | Improper Restriction of Operations within the Bounds of a Memory Buffer | Class | 12 | DoS, Execute Unauthorized Code or Commands, Modify Memory |
| [CWE-173](https://cwe.mitre.org/data/definitions/173.html) | Improper Handling of Alternate Encoding | Variant | 12 | Bypass Protection Mechanism |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) | Not Using Password Aging | Base | 12 | Gain Privileges or Assume Identity |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) | Password Aging with Long Expiration | Base | 12 | Gain Privileges or Assume Identity |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | Base | 12 | Bypass Protection Mechanism, Gain Privileges or Assume Identity |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | Class | 12 | Unexpected State, Varies by Context |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | Base | 12 | Alter Execution Logic, Execute Unauthorized Code or Commands, Other |
| [CWE-602](https://cwe.mitre.org/data/definitions/602.html) | Client-Side Enforcement of Server-Side Security | Class | 12 | Bypass Protection Mechanism, DoS, Gain Privileges or Assume Identity |
| [CWE-680](https://cwe.mitre.org/data/definitions/680.html) | Integer Overflow to Buffer Overflow | Compound | 11 | DoS, Execute Unauthorized Code or Commands, Modify Memory |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | Class | 11 | Gain Privileges or Assume Identity, Modify Application Data, Other |
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | External Control of System or Configuration Setting | Base | 10 | Varies by Context |
| [CWE-172](https://cwe.mitre.org/data/definitions/172.html) | Encoding Error | Class | 10 | Unexpected State |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | Class | 10 | Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity, Read Application Data |
| [CWE-290](https://cwe.mitre.org/data/definitions/290.html) | Authentication Bypass by Spoofing | Base | 10 | Bypass Protection Mechanism, Gain Privileges or Assume Identity |
| [CWE-294](https://cwe.mitre.org/data/definitions/294.html) | Authentication Bypass by Capture-replay | Base | 10 | Gain Privileges or Assume Identity |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) | Reliance on a Single Factor in a Security Decision | Base | 10 | Gain Privileges or Assume Identity, Hide Activities |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | Incomplete List of Disallowed Inputs | Base | 9 | Bypass Protection Mechanism |
| [CWE-201](https://cwe.mitre.org/data/definitions/201.html) | Insertion of Sensitive Information Into Sent Data | Base | 9 | Read Application Data, Read Files or Directories, Read Memory |
| [CWE-300](https://cwe.mitre.org/data/definitions/300.html) | Channel Accessible by Non-Endpoint | Class | 9 | Gain Privileges or Assume Identity, Modify Application Data, Read Application Data |
| [CWE-521](https://cwe.mitre.org/data/definitions/521.html) | Weak Password Requirements | Base | 9 | Gain Privileges or Assume Identity |
| [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | External Control of File Name or Path | Base | 8 | DoS, Execute Unauthorized Code or Commands, Modify Files or Directories |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Improper Neutralization of Special Elements used in a Command ('Command Injection') | Class | 8 | Execute Unauthorized Code or Commands |
| [CWE-118](https://cwe.mitre.org/data/definitions/118.html) | Incorrect Access of Indexable Resource ('Range Error') | Class | 8 | Varies by Context |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) | Authentication Bypass by Assumed-Immutable Data | Base | 8 | Bypass Protection Mechanism |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) | Incorrect Behavior Order: Validate Before Filter | Variant | 7 | Bypass Protection Mechanism |

---

## Weakness classes

The Class-level weaknesses — the practical taxonomy most secure-coding and testing work maps to.

| CWE | Class | Consequences | Example mitigation |
|---|---|---|---|
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | DoS, Execute Unauthorized Code or Commands | Consider using language-theoretic security (LangSec) techniques that characterize inputs u |
| [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | Alter Execution Logic, Bypass Protection Mechanism | Programming languages and supporting technologies might be chosen which are not subject to |
| [CWE-75](https://cwe.mitre.org/data/definitions/75.html) | Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) | Execute Unauthorized Code or Commands, Modify Application Data | Programming languages and supporting technologies might be chosen which are not subject to |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Improper Neutralization of Special Elements used in a Command ('Command Injection') | Execute Unauthorized Code or Commands | If at all possible, use library calls rather than external processes to recreate the desir |
| [CWE-99](https://cwe.mitre.org/data/definitions/99.html) | Improper Control of Resource Identifiers ('Resource Injection') | Modify Application Data, Modify Files or Directories | Assume all input is malicious. Use an accept known good input validation strategy, i.e., u |
| [CWE-114](https://cwe.mitre.org/data/definitions/114.html) | Process Control | Execute Unauthorized Code or Commands | Libraries that are loaded should be well understood and come from a trusted source. The ap |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Improper Encoding or Escaping of Output | Bypass Protection Mechanism, Execute Unauthorized Code or Commands | Use a vetted library or framework that does not allow this weakness to occur or provides c |
| [CWE-118](https://cwe.mitre.org/data/definitions/118.html) | Incorrect Access of Indexable Resource ('Range Error') | Varies by Context | — |
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) | Improper Restriction of Operations within the Bounds of a Memory Buffer | DoS, Execute Unauthorized Code or Commands | Use a language that does not allow this weakness to occur or provides constructs that make |
| [CWE-138](https://cwe.mitre.org/data/definitions/138.html) | Improper Neutralization of Special Elements | Alter Execution Logic, DoS | Developers should anticipate that special elements (e.g. delimiters, symbols) will be inje |
| [CWE-159](https://cwe.mitre.org/data/definitions/159.html) | Improper Handling of Invalid Use of Special Elements | Unexpected State | Developers should anticipate that special elements will be injected/removed/manipulated in |
| [CWE-172](https://cwe.mitre.org/data/definitions/172.html) | Encoding Error | Unexpected State | Assume all input is malicious. Use an accept known good input validation strategy, i.e., u |
| [CWE-185](https://cwe.mitre.org/data/definitions/185.html) | Incorrect Regular Expression | Bypass Protection Mechanism, Unexpected State | Regular expressions can become error prone when defining a complex language even for those |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information to an Unauthorized Actor | Read Application Data | Compartmentalize the system to have safe areas where trust boundaries can be unambiguously |
| [CWE-216](https://cwe.mitre.org/data/definitions/216.html) | DEPRECATED: Containment Errors (Container Errors) | — | — |
| [CWE-221](https://cwe.mitre.org/data/definitions/221.html) | Information Loss or Omission | Hide Activities | — |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) | Improper Handling of Syntactically Invalid Structure | DoS, Unexpected State | — |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | Improper Privilege Management | Gain Privileges or Assume Identity | Very carefully manage the setting, management, and handling of privileges. Explicitly mana |
| [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | Privilege Dropping / Lowering Errors | Gain Privileges or Assume Identity, Hide Activities | Compartmentalize the system to have safe areas where trust boundaries can be unambiguously |
| [CWE-282](https://cwe.mitre.org/data/definitions/282.html) | Improper Ownership Management | Gain Privileges or Assume Identity | Very carefully manage the setting, management, and handling of privileges. Explicitly mana |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity | Divide the product into anonymous, normal, privileged, and administrative areas. Reduce th |
| [CWE-286](https://cwe.mitre.org/data/definitions/286.html) | Incorrect User Management | Varies by Context | — |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity | Use an authentication framework or library such as the OWASP ESAPI Authentication feature. |
| [CWE-300](https://cwe.mitre.org/data/definitions/300.html) | Channel Accessible by Non-Endpoint | Gain Privileges or Assume Identity, Modify Application Data | Always fully authenticate both ends of any communications channel. |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Missing Encryption of Sensitive Data | Modify Application Data, Read Application Data | Clearly specify which data or resources are valuable enough that they should be protected  |
| [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | Inadequate Encryption Strength | Bypass Protection Mechanism, Read Application Data | Use an encryption scheme that is currently considered to be strong by experts in the field |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Use of a Broken or Risky Cryptographic Algorithm | Hide Activities, Modify Application Data | When there is a need to store or transmit sensitive data, use strong, up-to-date cryptogra |
| [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | Use of Insufficiently Random Values | Bypass Protection Mechanism, Gain Privileges or Assume Identity | Use a well-vetted algorithm that is currently considered to be strong by experts in the fi |
| [CWE-340](https://cwe.mitre.org/data/definitions/340.html) | Generation of Predictable Numbers or Identifiers | Varies by Context | — |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | Unexpected State, Varies by Context | — |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | Gain Privileges or Assume Identity, Varies by Context | — |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | Bypass Protection Mechanism, DoS | In languages that support it, use synchronization primitives. Only wrap these around criti |
| [CWE-377](https://cwe.mitre.org/data/definitions/377.html) | Insecure Temporary File | Modify Files or Directories, Read Files or Directories | — |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled Resource Consumption | Bypass Protection Mechanism, DoS | Design throttling mechanisms into the system architecture. The best protection is to limit |
| [CWE-402](https://cwe.mitre.org/data/definitions/402.html) | Transmission of Private Resources into a New Sphere ('Resource Leak') | Read Application Data | — |
| [CWE-404](https://cwe.mitre.org/data/definitions/404.html) | Improper Resource Shutdown or Release | DoS, Read Application Data | Use a language that does not allow this weakness to occur or provides constructs that make |
| [CWE-405](https://cwe.mitre.org/data/definitions/405.html) | Asymmetric Resource Consumption (Amplification) | DoS | An application must make resources available to a client commensurate with the client's ac |
| [CWE-406](https://cwe.mitre.org/data/definitions/406.html) | Insufficient Control of Network Message Volume (Network Amplification) | DoS | An application must make network resources available to a client commensurate with the cli |
| [CWE-407](https://cwe.mitre.org/data/definitions/407.html) | Inefficient Algorithmic Complexity | DoS | — |
| [CWE-410](https://cwe.mitre.org/data/definitions/410.html) | Insufficient Resource Pool | DoS, Other | Do not perform resource-intensive transactions for unauthenticated users and/or invalid re |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | Bypass Protection Mechanism, Gain Privileges or Assume Identity | Deploy different layers of protection to implement security in depth. |
| [CWE-436](https://cwe.mitre.org/data/definitions/436.html) | Interpretation Conflict | Unexpected State, Varies by Context | — |
| [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | Unintended Proxy or Intermediary ('Confused Deputy') | Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity | Enforce the use of strong mutual authentication mechanism between the two parties. |
| [CWE-446](https://cwe.mitre.org/data/definitions/446.html) | UI Discrepancy for Security Feature | Varies by Context | — |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | User Interface (UI) Misrepresentation of Critical Information | Bypass Protection Mechanism, Hide Activities | Perform data validation (e.g. syntax, length, etc.) before interpreting the data. |
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | Execute Unauthorized Code or Commands | Remove the malicious code and start an effort to ensure that no more malicious code exists |
| [CWE-514](https://cwe.mitre.org/data/definitions/514.html) | Covert Channel | Bypass Protection Mechanism, Read Application Data | — |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | Gain Privileges or Assume Identity | Use an appropriate security mechanism to protect the credentials. |
| [CWE-573](https://cwe.mitre.org/data/definitions/573.html) | Improper Following of Specification by Caller | Quality Degradation, Varies by Context | — |
| [CWE-592](https://cwe.mitre.org/data/definitions/592.html) | DEPRECATED: Authentication Bypass Issues | — | — |
| [CWE-602](https://cwe.mitre.org/data/definitions/602.html) | Client-Side Enforcement of Server-Side Security | Bypass Protection Mechanism, DoS | For any security checks that are performed on the client side, ensure that these checks ar |
| [CWE-610](https://cwe.mitre.org/data/definitions/610.html) | Externally Controlled Reference to a Resource in Another Sphere | Gain Privileges or Assume Identity, Modify Application Data | — |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely ('Failing Open') | Bypass Protection Mechanism | Subdivide and allocate resources and components so that a failure in one part does not aff |
| [CWE-637](https://cwe.mitre.org/data/definitions/637.html) | Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | Other | Avoid complex security mechanisms when simpler ones would meet requirements. Avoid complex |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) | Not Using Complete Mediation | Bypass Protection Mechanism, Execute Unauthorized Code or Commands | Invalidate cached privileges, file handles or descriptors, or other access credentials whe |
| [CWE-642](https://cwe.mitre.org/data/definitions/642.html) | External Control of Critical State Data | Bypass Protection Mechanism, DoS | Understand all the potential locations that are accessible to attackers. For example, some |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) | Improper Isolation or Compartmentalization | Bypass Protection Mechanism, Gain Privileges or Assume Identity | Break up privileges between different modules, objects, or entities. Minimize the interfac |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) | Insufficient Psychological Acceptability | Bypass Protection Mechanism | Where possible, perform human factors and usability studies to identify where your product |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | Reliance on Security Through Obscurity | Other | Always consider whether knowledge of your code or design is sufficient to break it. Revers |
| [CWE-657](https://cwe.mitre.org/data/definitions/657.html) | Violation of Secure Design Principles | Other | — |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) | Improper Synchronization | Alter Execution Logic, Modify Application Data | Use industry standard APIs to synchronize your code. |
| [CWE-665](https://cwe.mitre.org/data/definitions/665.html) | Improper Initialization | Bypass Protection Mechanism, DoS | Use a language that does not allow this weakness to occur or provides constructs that make |
| [CWE-666](https://cwe.mitre.org/data/definitions/666.html) | Operation on Resource in Wrong Phase of Lifetime | Other | Follow the resource's lifecycle from creation to release. |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) | Improper Locking | DoS | Use industry standard APIs to implement locking mechanism. |
| [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | Exposure of Resource to Wrong Sphere | Modify Application Data, Read Application Data | — |
| [CWE-669](https://cwe.mitre.org/data/definitions/669.html) | Incorrect Resource Transfer Between Spheres | Modify Application Data, Read Application Data | — |
| [CWE-670](https://cwe.mitre.org/data/definitions/670.html) | Always-Incorrect Control Flow Implementation | Alter Execution Logic, Other | — |
| [CWE-671](https://cwe.mitre.org/data/definitions/671.html) | Lack of Administrator Control over Security | Varies by Context | — |
| [CWE-672](https://cwe.mitre.org/data/definitions/672.html) | Operation on a Resource after Expiration or Release | DoS, Modify Application Data | — |
| [CWE-673](https://cwe.mitre.org/data/definitions/673.html) | External Influence of Sphere Definition | Other | — |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) | Uncontrolled Recursion | DoS, Read Application Data | Ensure that an end condition will be reached under all logic conditions. The end condition |
| [CWE-675](https://cwe.mitre.org/data/definitions/675.html) | Multiple Operations on Resource in Single-Operation Context | Other | — |
| [CWE-684](https://cwe.mitre.org/data/definitions/684.html) | Incorrect Provision of Specified Functionality | Quality Degradation | Ensure that your code strictly conforms to specifications. |
| [CWE-696](https://cwe.mitre.org/data/definitions/696.html) | Incorrect Behavior Order | Alter Execution Logic | — |
| [CWE-704](https://cwe.mitre.org/data/definitions/704.html) | Incorrect Type Conversion or Cast | Other | — |
| [CWE-705](https://cwe.mitre.org/data/definitions/705.html) | Incorrect Control Flow Scoping | Alter Execution Logic, Other | — |
| [CWE-706](https://cwe.mitre.org/data/definitions/706.html) | Use of Incorrectly-Resolved Name or Reference | Modify Application Data, Read Application Data | — |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | Gain Privileges or Assume Identity, Modify Application Data | When using a critical resource such as a configuration file, check to see if the resource  |
| [CWE-754](https://cwe.mitre.org/data/definitions/754.html) | Improper Check for Unusual or Exceptional Conditions | DoS, Unexpected State | Use a language that does not allow this weakness to occur or provides constructs that make |
| [CWE-755](https://cwe.mitre.org/data/definitions/755.html) | Improper Handling of Exceptional Conditions | Other | — |
| [CWE-758](https://cwe.mitre.org/data/definitions/758.html) | Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | Quality Degradation, Reduce Maintainability | — |
| [CWE-790](https://cwe.mitre.org/data/definitions/790.html) | Improper Filtering of Special Elements | Unexpected State | — |
| [CWE-799](https://cwe.mitre.org/data/definitions/799.html) | Improper Control of Interaction Frequency | Bypass Protection Mechanism, DoS | — |
| [CWE-834](https://cwe.mitre.org/data/definitions/834.html) | Excessive Iteration | DoS | — |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | Improper Enforcement of Behavioral Workflow | Alter Execution Logic | — |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing Authorization | Bypass Protection Mechanism, DoS | Divide the product into anonymous, normal, privileged, and administrative areas. Reduce th |
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect Authorization | Bypass Protection Mechanism, DoS | Divide the product into anonymous, normal, privileged, and administrative areas. Reduce th |
| [CWE-909](https://cwe.mitre.org/data/definitions/909.html) | Missing Initialization of Resource | DoS, Read Application Data | Explicitly initialize the resource before use. If this is performed through an API functio |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) | Hidden Functionality | Alter Execution Logic, Varies by Context | Always verify the integrity of the product that is being installed. |
| [CWE-913](https://cwe.mitre.org/data/definitions/913.html) | Improper Control of Dynamically-Managed Code Resources | Alter Execution Logic, Execute Unauthorized Code or Commands | For any externally-influenced input, check the input against an allowlist of acceptable va |
| [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | Insecure Storage of Sensitive Information | Modify Application Data, Modify Files or Directories | — |
| [CWE-923](https://cwe.mitre.org/data/definitions/923.html) | Improper Restriction of Communication Channel to Intended Endpoints | Gain Privileges or Assume Identity | — |
| [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | Improper Neutralization of Special Elements in Data Query Logic | Bypass Protection Mechanism, Modify Application Data | — |
| [CWE-1023](https://cwe.mitre.org/data/definitions/1023.html) | Incomplete Comparison with Missing Factors | Alter Execution Logic, Bypass Protection Mechanism | — |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) | Insecure Automated Optimizations | Alter Execution Logic | — |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | Bypass Protection Mechanism, DoS | Algorithmic modifications such as model pruning or compression can help mitigate this weak |
| [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | Insufficient Technical Documentation | Hide Activities, Quality Degradation | Ensure that design documentation is detailed enough to allow for post-manufacturing verifi |
| [CWE-1061](https://cwe.mitre.org/data/definitions/1061.html) | Insufficient Encapsulation | Bypass Protection Mechanism, Increase Analytical Complexity | — |
| [CWE-1076](https://cwe.mitre.org/data/definitions/1076.html) | Insufficient Adherence to Expected Conventions | Reduce Maintainability | — |
| [CWE-1078](https://cwe.mitre.org/data/definitions/1078.html) | Inappropriate Source Code Style or Formatting | Increase Analytical Complexity | — |
| [CWE-1093](https://cwe.mitre.org/data/definitions/1093.html) | Excessively Complex Data Representation | Increase Analytical Complexity, Reduce Maintainability | — |
| [CWE-1120](https://cwe.mitre.org/data/definitions/1120.html) | Excessive Code Complexity | Increase Analytical Complexity, Reduce Maintainability | — |
| [CWE-1164](https://cwe.mitre.org/data/definitions/1164.html) | Irrelevant Code | Reduce Performance, Reduce Reliability | — |
| [CWE-1176](https://cwe.mitre.org/data/definitions/1176.html) | Inefficient CPU Computation | DoS, Reduce Performance | — |
| [CWE-1177](https://cwe.mitre.org/data/definitions/1177.html) | Use of Prohibited Code | Reduce Maintainability | Identify a list of prohibited API functions and prohibit developers from using these funct |
| [CWE-1229](https://cwe.mitre.org/data/definitions/1229.html) | Creation of Emergent Resource | Varies by Context | — |
| [CWE-1263](https://cwe.mitre.org/data/definitions/1263.html) | Improper Physical Access Control | Varies by Context | Specific protection requirements depend strongly on contextual factors including the level |
| [CWE-1294](https://cwe.mitre.org/data/definitions/1294.html) | Insecure Security Identifier Mechanism | DoS, Execute Unauthorized Code or Commands | Security Identifier Decoders must be reviewed for design inconsistency and common weakness |
| [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | Reliance on Insufficiently Trustworthy Component | Reduce Maintainability | For each component, ensure that its supply chain is well-controlled with sub-tier supplier |
| [CWE-1384](https://cwe.mitre.org/data/definitions/1384.html) | Improper Handling of Physical or Environmental Conditions | Unexpected State, Varies by Context | In requirements, be specific about expectations for how the product will perform when it e |
| [CWE-1390](https://cwe.mitre.org/data/definitions/1390.html) | Weak Authentication | Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity | — |
| [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) | Use of Weak Credentials | Bypass Protection Mechanism | When the user changes or sets a password, check the password against a database of already |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Dependency on Vulnerable Third-Party Component | Varies by Context | In some industries such as healthcare [REF-1320] [REF-1322] or technologies such as the cl |
| [CWE-1419](https://cwe.mitre.org/data/definitions/1419.html) | Incorrect Initialization of Resource | Gain Privileges or Assume Identity, Read Application Data | Choose the safest-possible initialization for security-related resources. |

---

*Source: MITRE CWE (CSV export, 969 entries). Consequences/mitigations summarized; see the official CWE pages for full detail.*
