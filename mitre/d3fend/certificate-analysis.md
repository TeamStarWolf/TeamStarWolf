# D3FEND: Certificate Analysis

<a id="certificate-analysis"></a>

**D3FEND tactic:** Detect  
**Digital artifacts:** Certificate File  

Analyzing Public Key Infrastructure certificates to detect if they have been misconfigured or spoofed using both network traffic, certificate fields and third-party logs.

## ATT&CK techniques countered (6)

- [T1041 — Exfiltration Over C2 Channel](/mitre/techniques/T1041.md) — analyzes. Adversaries may steal data by exfiltrating it over an existing command and control channel.
- [T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-002.md) — analyzes. Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel.
- [T1071 — Application Layer Protocol](/mitre/techniques/T1071.md) — analyzes. Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- [T1071.001 — Web Protocols](/mitre/techniques/T1071-001.md) — analyzes. Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- [T1573.002 — Asymmetric Cryptography](/mitre/techniques/T1573-002.md) — analyzes. Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1649 — Steal or Forge Authentication Certificates](/mitre/techniques/T1649.md) — analyzes. Adversaries may steal or forge certificates used for authentication to access remote systems or resources.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
