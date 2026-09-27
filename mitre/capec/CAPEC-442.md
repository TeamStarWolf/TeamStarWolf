# CAPEC-442 — Infected Software

<a id="capec-442"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary adds malicious logic, often in the form of a computer virus, to otherwise benign software. This logic is often hidden from the user of the software and works behind the scenes to achieve negative impacts. Many times, the malicious logic is inserted into empty space between legitimate code, and is then called when the software is executed. This pattern of attack focuses on software alr

## Mapped ATT&CK techniques (2)

- [T1195.001](/mitre/techniques/T1195-001.md)
- [T1195.002](/mitre/techniques/T1195-002.md)

## Related CWE (1)

[CWE-506](/CWE_REFERENCE.md)

**Prerequisites:** ::Access to the software currently deployed at a victim location. This access is often obtained by leveraging another attack pattern to gain permissions that the adversary wouldn't normally have.::

**Mitigations:** ::Leverage anti-virus products to detect and quarantine software with known virus.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
