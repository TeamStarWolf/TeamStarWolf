# CAPEC-682 — Exploitation of Firmware or ROM Code with Unpatchable Vulnerabilities

<a id="capec-682"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary may exploit vulnerable code (i.e., firmware or ROM) that is unpatchable. Unpatchable devices exist due to manufacturers intentionally or inadvertently designing devices incapable of updating their software. Additionally, with updatable devices, the manufacturer may decide not to support the device and stop making updates to their software.

## Related CWE (2)

[CWE-1277](/CWE_REFERENCE.md) [CWE-1310](/CWE_REFERENCE.md)

**Prerequisites:** ::Awareness of the hardware being leveraged.::Access to the hardware being leveraged, either physically or remotely.::

**Skills required:** ::SKILL:Knowledge of various wireless protocols to enable remote access to vulnerable devices:LEVEL:Medium::SKILL:Ability to identify physical entry p

**Mitigations:** ::Design systems and products with the ability to patch firmware or ROM code after deployment to fix vulnerabilities.::Make use of OTA (Over-the-air) updates so that firmware can be patched remotely either through manual or automatic means::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
