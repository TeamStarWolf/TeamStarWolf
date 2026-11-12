# D3FEND: Certificate Analysis

<a id="certificate-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: Certificate File  

Analyzing Public Key Infrastructure certificates to detect if they have been misconfigured or spoofed using both network traffic, certificate fields and third-party logs.

## ATT&CK techniques countered (6)

- [T1041: Exfiltration Over C2 Channel](/mitre/techniques/T1041.md): analyzes. Adversaries may steal data by exfiltrating it over an existing command and control channel.
- [T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-002.md): analyzes. Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel.
- [T1071: Application Layer Protocol](/mitre/techniques/T1071.md): analyzes. Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- [T1071.001: Web Protocols](/mitre/techniques/T1071-001.md): analyzes. Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- [T1573.002: Asymmetric Cryptography](/mitre/techniques/T1573-002.md): analyzes. Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1649: Steal or Forge Authentication Certificates](/mitre/techniques/T1649.md): analyzes. Adversaries may steal or forge certificates used for authentication to access remote systems or resources.

## Related pages

- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 6 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 6 of these techniques
- [Content Quarantine](/mitre/d3fend/content-quarantine.md), which also counters 6 of these techniques
- [Decoy File](/mitre/d3fend/decoy-file.md), which also counters 6 of these techniques
- [File Analysis](/mitre/d3fend/file-analysis.md), which also counters 6 of these techniques
- [File Encryption](/mitre/d3fend/file-encryption.md), which also counters 6 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
