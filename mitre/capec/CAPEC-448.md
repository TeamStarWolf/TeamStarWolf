# CAPEC-448: Embed Virus into DLL

<a id="capec-448"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary tampers with a DLL and embeds a computer virus into gaps between legitimate machine instructions. These gaps may be the result of compiler optimizations that pad memory blocks for performance gains. The embedded virus then attempts to infect any machine which interfaces with the product, and possibly steal private data or eavesdrop.

## Mapped ATT&CK techniques (1)

- [T1027.009: Embedded Payloads](/mitre/techniques/T1027-009.md): Adversaries may embed payloads within other files to conceal malicious content from defenses.

## Related CWE (1)

- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html): The product contains code that appears to be malicious in nature.

## Prerequisites

- Access to the software currently deployed at a victim location. This access is often obtained by leveraging another attack pattern to gain permissions that the adversary wouldn't normally have.

## Consequences

- Authorization / Execute Unauthorized Commands

## Mitigations

- Leverage anti-virus products to detect and quarantine software with known virus.

## Related pages

- [CAPEC-442: Infected Software](/mitre/capec/CAPEC-442.md), also related to CWE-506
- [CAPEC-636: Hiding Malicious Data or Code within Files](/mitre/capec/CAPEC-636.md), also related to CWE-506
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The European Commission Cloud Breach of 2026: AWS Data Theft Through the Poisoned Trivy Scanner](/case-studies/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
