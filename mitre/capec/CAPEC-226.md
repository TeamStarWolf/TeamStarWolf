# CAPEC-226: Session Credential Falsification through Manipulation

<a id="capec-226"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in order to gain access to a target server.

## Related CWE (2)

- [CWE-565: Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html): The product relies on the existence or values of cookies when performing security-critical operations, but it does not properly ensure that the setting is valid for the associated user.
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html): The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.

## Prerequisites

- The targeted application must use session credentials to identify legitimate users.

## Related pages

- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](/mitre/capec/CAPEC-31.md), also related to CWE-472 and CWE-565
- [CAPEC-39: Manipulating Opaque Client-based Data Tokens](/mitre/capec/CAPEC-39.md), also related to CWE-472 and CWE-565
- [CAPEC-146: XML Schema Poisoning](/mitre/capec/CAPEC-146.md), also related to CWE-472
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
