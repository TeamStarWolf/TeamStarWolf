# CAPEC-474: Signature Spoofing by Key Theft

<a id="capec-474"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An attacker obtains an authoritative or reputable signer's private signature key by theft and then uses this key to forge signatures from the original signer to mislead a victim into performing actions that benefit the attacker.

## Mapped ATT&CK techniques (1)

- [T1552.004: Private Keys](/mitre/techniques/T1552-004.md): Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.

## Related CWE (1)

- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html): The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Prerequisites

- An authoritative or reputable signer is storing their private signature key with insufficient protection.

## Skills required

- [Low] Knowledge of common location methods and access methods to sensitive data
- [High] Ability to compromise systems containing sensitive data

## Mitigations

- Restrict access to private keys from non-supervisory accounts
- Restrict access to administrative personnel and processes only
- Ensure all remote methods are secured
- Ensure all services are patched and up to date

## Related pages

- [CAPEC-50: Password Recovery Exploitation](/mitre/capec/CAPEC-50.md), also related to CWE-522
- [CAPEC-102: Session Sidejacking](/mitre/capec/CAPEC-102.md), also related to CWE-522
- [CAPEC-509: Kerberoasting](/mitre/capec/CAPEC-509.md), also related to CWE-522
- [CAPEC-551: Modify Existing Service](/mitre/capec/CAPEC-551.md), also related to CWE-522
- [CAPEC-555: Remote Services with Stolen Credentials](/mitre/capec/CAPEC-555.md), also related to CWE-522
- [CAPEC-560: Use of Known Domain Credentials](/mitre/capec/CAPEC-560.md), also related to CWE-522
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
