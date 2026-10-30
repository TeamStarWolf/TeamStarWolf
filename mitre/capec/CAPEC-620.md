# CAPEC-620: Drop Encryption Level

<a id="capec-620"></a>

Abstraction: Standard  
Typical severity: High  
Status: Draft  
OpenCRE: [CAPEC-620](https://opencre.org/smartlink/standard/CAPEC/620)  

An attacker forces the encryption level to be lowered, thus enabling a successful attack against the encrypted data.

## Mapped ATT&CK techniques (1)

- [T1600: Weaken Encryption](/mitre/techniques/T1600.md): Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.

## Related CWE (1)

- [CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html): A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it does not select the strongest algorithm that is available to both parties.

## Consequences

- Access Control / Bypass Protection Mechanism

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
