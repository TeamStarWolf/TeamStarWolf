# CAPEC-474 — Signature Spoofing by Key Theft

<a id="capec-474"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An attacker obtains an authoritative or reputable signer's private signature key by theft and then uses this key to forge signatures from the original signer to mislead a victim into performing actions that benefit the attacker.

## Mapped ATT&CK techniques (1)

- [T1552.004](/mitre/techniques/T1552-004.md)

## Related CWE (1)

[CWE-522](/CWE_REFERENCE.md)

**Prerequisites:** ::An authoritative or reputable signer is storing their private signature key with insufficient protection.::

**Skills required:** ::SKILL:Knowledge of common location methods and access methods to sensitive data:LEVEL:Low::SKILL:Ability to compromise systems containing sensitive 

**Mitigations:** ::Restrict access to private keys from non-supervisory accounts::Restrict access to administrative personnel and processes only::Ensure all remote methods are secured::Ensure all services are patched and up to date::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
