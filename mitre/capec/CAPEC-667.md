# CAPEC-667: Bluetooth Impersonation AttackS (BIAS)

<a id="capec-667"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary disguises the MAC address of their Bluetooth enabled device to one for which there exists an active and trusted connection and authenticates successfully. The adversary can then perform malicious actions on the target Bluetooth device depending on the target’s capabilities.

## Related CWE (1)

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html): This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Prerequisites

- Knowledge of a target device's list of trusted connections.

## Skills required

- [Low] Adversaries must be capable of using command line Linux tools.
- [Low] Adversaries must be in close proximity to Bluetooth devices.

## Consequences

- Integrity
- Confidentiality

## Mitigations

- Disable Bluetooth in public places.
- Verify incoming Bluetooth connections; do not automatically trust.
- Change default PIN passwords and always use one when connecting.

## Related pages

- [CAPEC-21: Exploitation of Trusted Identifiers](/mitre/capec/CAPEC-21.md), also related to CWE-290
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-290
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-290
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-290
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-290
- [CAPEC-459: Creating a Rogue Certification Authority Certificate](/mitre/capec/CAPEC-459.md), also related to CWE-290
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
