# D3FEND: IO Port Restriction

<a id="io-port-restriction"></a>

D3FEND tactic: Isolate  
Digital artifacts: Removable Media Device, I/O Module, Input Device  

Limiting access to computer input/output (IO) ports to restrict unauthorized devices.

## ATT&CK techniques countered (9)

- [T0847](https://attack.mitre.org/techniques/T0847): filters
- [T0860](https://attack.mitre.org/techniques/T0860): isolates
- [T1025: Data from Removable Media](/mitre/techniques/T1025.md): filters. Adversaries may search connected removable media on computers they have compromised to find files of interest.
- [T1052.001: Exfiltration over USB](/mitre/techniques/T1052-001.md): filters. Adversaries may attempt to exfiltrate data over a USB connected physical device.
- [T1056.001: Keylogging](/mitre/techniques/T1056-001.md): filters. Adversaries may log user keystrokes to intercept credentials as the user types them.
- [T1091: Replication Through Removable Media](/mitre/techniques/T1091.md): filters. Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.
- [T1092: Communication Through Removable Media](/mitre/techniques/T1092.md): filters. Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.
- [T1123: Audio Capture](/mitre/techniques/T1123.md): filters. An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.
- [T1125: Video Capture](/mitre/techniques/T1125.md): filters. An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
