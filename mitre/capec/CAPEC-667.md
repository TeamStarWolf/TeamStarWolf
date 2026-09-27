# CAPEC-667 — Bluetooth Impersonation AttackS (BIAS)

<a id="capec-667"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary disguises the MAC address of their Bluetooth enabled device to one for which there exists an active and trusted connection and authenticates successfully. The adversary can then perform malicious actions on the target Bluetooth device depending on the target’s capabilities.

## Related CWE (1)

[CWE-290](/CWE_REFERENCE.md)

**Prerequisites:** ::Knowledge of a target device's list of trusted connections.::

**Skills required:** ::SKILL:Adversaries must be capable of using command line Linux tools.:LEVEL:Low::SKILL:Adversaries must be in close proximity to Bluetooth devices.:L

**Mitigations:** ::Disable Bluetooth in public places.::Verify incoming Bluetooth connections; do not automatically trust.::Change default PIN passwords and always use one when connecting.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
