# D3FEND: IO Port Restriction

<a id="io-port-restriction"></a>

D3FEND tactic: Isolate  
Digital artifacts: I/O Module, Input Device, Removable Media Device  

Limiting access to computer input/output (IO) ports to restrict unauthorized devices.

## ATT&CK techniques countered (9)

- [T0847: Replication Through Removable Media](https://attack.mitre.org/techniques/T0847): filters
- [T0860: Wireless Compromise](https://attack.mitre.org/techniques/T0860): isolates
- [T1025: Data from Removable Media](/mitre/techniques/T1025.md): filters. Adversaries may search connected removable media on computers they have compromised to find files of interest.
- [T1052.001: Exfiltration over USB](/mitre/techniques/T1052-001.md): filters. Adversaries may attempt to exfiltrate data over a USB connected physical device.
- [T1056.001: Keylogging](/mitre/techniques/T1056-001.md): filters. Adversaries may log user keystrokes to intercept credentials as the user types them.
- [T1091: Replication Through Removable Media](/mitre/techniques/T1091.md): filters. Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.
- [T1092: Communication Through Removable Media](/mitre/techniques/T1092.md): filters. Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.
- [T1123: Audio Capture](/mitre/techniques/T1123.md): filters. An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.
- [T1125: Video Capture](/mitre/techniques/T1125.md): filters. An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information.

## Related pages

- [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md), which also counters 9 of these techniques
- [Radiation Hardening](/mitre/d3fend/radiation-hardening.md), which also counters 9 of these techniques
- [Input Device Analysis](/mitre/d3fend/input-device-analysis.md), which also counters 3 of these techniques
- [Directional Network Link](/mitre/d3fend/directional-network-link.md), which also counters 1 of these techniques
- [Physical Link Mapping](/mitre/d3fend/physical-link-mapping.md), which also counters 1 of these techniques
- [Video Surveillance](/mitre/d3fend/video-surveillance.md), which also counters 1 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)
- [The Year 2014 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2014.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
