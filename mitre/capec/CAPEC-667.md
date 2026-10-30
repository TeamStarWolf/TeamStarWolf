# CAPEC-667: Bluetooth Impersonation AttackS (BIAS)

<a id="capec-667"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  
OpenCRE: [CAPEC-667](https://opencre.org/smartlink/standard/CAPEC/667)  

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

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
