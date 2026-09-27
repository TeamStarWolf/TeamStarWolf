# CAPEC-668 — Key Negotiation of Bluetooth Attack (KNOB)

<a id="capec-668"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An adversary can exploit a flaw in Bluetooth key negotiation allowing them to decrypt information sent between two devices communicating via Bluetooth. The adversary uses an Adversary in the Middle setup to modify packets sent between the two devices during the authentication process, specifically the entropy bits. Knowledge of the number of entropy bits will allow the attacker to easily decrypt i

## Mapped ATT&CK techniques (1)

- [T1565.002](/mitre/techniques/T1565-002.md)

## Related CWE (3)

[CWE-425](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md)

**Prerequisites:** ::Person in the Middle network setup.::

**Skills required:** ::SKILL:Ability to modify packets.:LEVEL:Medium::

**Mitigations:** ::Newer Bluetooth firmwares ensure that the KNOB is not negotaited in plaintext. Update your device.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
