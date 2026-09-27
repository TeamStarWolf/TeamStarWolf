# CAPEC-505 — Scheme Squatting

<a id="capec-505"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary, through a previously installed malicious application, registers for a URL scheme intended for a target application that has not been installed. Thereafter, messages intended for the target application are handled by the malicious application. Upon receiving a message, the malicious application displays a screen that mimics the target application, thereby convincing the user to enter sensitive information. This type of attack is most often used to obtain sensitive information (e.g., credentials) from the user as they think that they are interacting with the intended target application.

## Mitigations

- The only known mitigation to this attack is to avoid installing the malicious application on the device. Applications usually have to declare the schemes they wish to register, so detecting this during a review is feasible.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
