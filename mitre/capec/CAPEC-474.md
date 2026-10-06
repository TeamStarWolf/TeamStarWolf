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

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
