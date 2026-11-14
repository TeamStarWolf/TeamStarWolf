# D3FEND: Hardware Component Inventory

<a id="hardware-component-inventory"></a>

D3FEND tactic: Model  
Digital artifacts: Hardware Device  

Hardware component inventorying identifies and records the hardware items in the organization's architecture.

## ATT&CK techniques countered (13)

- [T0847: Replication Through Removable Media](https://attack.mitre.org/techniques/T0847): inventories
- [T0860: Wireless Compromise](https://attack.mitre.org/techniques/T0860): inventories
- [T1025: Data from Removable Media](/mitre/techniques/T1025.md): inventories. Adversaries may search connected removable media on computers they have compromised to find files of interest.
- [T1052.001: Exfiltration over USB](/mitre/techniques/T1052-001.md): inventories. Adversaries may attempt to exfiltrate data over a USB connected physical device.
- [T1056.001: Keylogging](/mitre/techniques/T1056-001.md): inventories. Adversaries may log user keystrokes to intercept credentials as the user types them.
- [T1091: Replication Through Removable Media](/mitre/techniques/T1091.md): inventories. Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.
- [T1092: Communication Through Removable Media](/mitre/techniques/T1092.md): inventories. Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.
- [T1111: Multi-Factor Authentication Interception](/mitre/techniques/T1111.md): inventories. Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources.
- [T1123: Audio Capture](/mitre/techniques/T1123.md): inventories. An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.
- [T1125: Video Capture](/mitre/techniques/T1125.md): inventories. An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information.
- [T1195.003: Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md): inventories. Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.
- [T1200: Hardware Additions](/mitre/techniques/T1200.md): inventories. Adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access.
- [T1619: Cloud Storage Object Discovery](/mitre/techniques/T1619.md): inventories. Adversaries may enumerate objects in cloud storage infrastructure.

## Related pages

- [Radiation Hardening](/mitre/d3fend/radiation-hardening.md), which also counters 13 of these techniques
- [IO Port Restriction](/mitre/d3fend/io-port-restriction.md), which also counters 9 of these techniques
- [Input Device Analysis](/mitre/d3fend/input-device-analysis.md), which also counters 3 of these techniques
- [Directional Network Link](/mitre/d3fend/directional-network-link.md), which also counters 1 of these techniques
- [Disk Encryption](/mitre/d3fend/disk-encryption.md), which also counters 1 of these techniques
- [Disk Erasure](/mitre/d3fend/disk-erasure.md), which also counters 1 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [The Year 2008 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2008.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
