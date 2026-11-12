# CAPEC-478: Modification of Windows Service Configuration

<a id="capec-478"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Usable  

An adversary exploits a weakness in access control to modify the execution parameters of a Windows service. The goal of this attack is to execute a malicious binary in place of an existing service.

## Mapped ATT&CK techniques (2)

- [T1574.011: Services Registry Permissions Weakness](/mitre/techniques/T1574-011.md): Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
- [T1543.003: Windows Service](/mitre/techniques/T1543-003.md): Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- The adversary must have the capability to write to the Windows Registry on the targeted system.

## Consequences

- Integrity / Execute Unauthorized Commands

## Mitigations

- Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.

## Related pages

- [CAPEC-19: Embedding Scripts within Scripts](/mitre/capec/CAPEC-19.md), also related to CWE-284
- [CAPEC-441: Malicious Logic Insertion](/mitre/capec/CAPEC-441.md), also related to CWE-284
- [CAPEC-479: Malicious Root Certificate](/mitre/capec/CAPEC-479.md), also related to CWE-284
- [CAPEC-502: Intent Spoof](/mitre/capec/CAPEC-502.md), also related to CWE-284
- [CAPEC-503: WebView Exposure](/mitre/capec/CAPEC-503.md), also related to CWE-284
- [CAPEC-536: Data Injected During Configuration](/mitre/capec/CAPEC-536.md), also related to CWE-284
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
