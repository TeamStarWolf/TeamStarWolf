# CAPEC-516 — Hardware Component Substitution During Baselining

<a id="capec-516"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary with access to system components during allocated baseline development can substitute a maliciously altered hardware component for a baseline component during the product development and research phases. This can lead to adjustments and calibrations being made in the product so that when the final product, now containing the modified component, is deployed it will not perform as desig

## Mapped ATT&CK techniques (1)

- [T1195.003](/mitre/techniques/T1195-003.md)

**Prerequisites:** ::The adversary will need either physical access or be able to supply malicious hardware components to the product development facility.::

**Skills required:** ::SKILL:Intelligence data on victim's purchasing habits.:LEVEL:Medium::SKILL:Resources to maliciously construct/alter hardware components used for tes

**Mitigations:** ::Hardware attacks are often difficult to detect, as inserted components can be difficult to identify or remain dormant for an extended period of time.::Acquire hardware and hardware components from trusted vendors. Additionally, determine where vend


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
