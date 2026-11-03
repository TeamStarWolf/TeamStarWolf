# CAPEC-551: Modify Existing Service

<a id="capec-551"></a>

Abstraction: Detailed  
Status: Draft  

When an operating system starts, it also starts programs called services or daemons. Modifying existing services may break existing services or may enable services that are disabled/not commonly used.

## Mapped ATT&CK techniques (1)

- [T1543: Create or Modify System Process](/mitre/techniques/T1543.md): Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.

## Related CWE (2)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html): The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Mitigations

- Limit privileges of user accounts so service changes can only be performed by authorized administrators. Also monitor any service changes that may occur inadvertently.

## Related pages

- [CAPEC-50: Password Recovery Exploitation](/mitre/capec/CAPEC-50.md), also related to CWE-522
- [CAPEC-102: Session Sidejacking](/mitre/capec/CAPEC-102.md), also related to CWE-522
- [CAPEC-474: Signature Spoofing by Key Theft](/mitre/capec/CAPEC-474.md), also related to CWE-522
- [CAPEC-509: Kerberoasting](/mitre/capec/CAPEC-509.md), also related to CWE-522
- [CAPEC-555: Remote Services with Stolen Credentials](/mitre/capec/CAPEC-555.md), also related to CWE-522
- [CAPEC-560: Use of Known Domain Credentials](/mitre/capec/CAPEC-560.md), also related to CWE-522
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
