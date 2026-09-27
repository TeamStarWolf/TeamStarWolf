# D3FEND: Outbound Traffic Filtering

<a id="outbound-traffic-filtering"></a>

**D3FEND tactic:** Isolate  
**Digital artifacts:** Outbound Network Traffic  

Restricting network traffic originating from a private host or enclave destined towards untrusted networks.

## ATT&CK techniques countered (32)

- [T0869](https://attack.mitre.org/techniques/T0869) — filters
- [T0884](https://attack.mitre.org/techniques/T0884) — filters
- [T1001 — Data Obfuscation](/mitre/techniques/T1001.md) — filters. Adversaries may obfuscate command and control traffic to make it more difficult to detect.
- [T1008 — Fallback Channels](/mitre/techniques/T1008.md) — filters. Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.
- [T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-001.md) — filters. Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel.
- [T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-002.md) — filters. Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel.
- [T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol](/mitre/techniques/T1048-003.md) — filters. Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
- [T1071 — Application Layer Protocol](/mitre/techniques/T1071.md) — filters. Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- [T1071.001 — Web Protocols](/mitre/techniques/T1071-001.md) — filters. Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- [T1071.002 — File Transfer Protocols](/mitre/techniques/T1071-002.md) — filters. Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic.
- [T1071.003 — Mail Protocols](/mitre/techniques/T1071-003.md) — filters. Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic.
- [T1071.004 — DNS](/mitre/techniques/T1071-004.md) — filters. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1090.002 — External Proxy](/mitre/techniques/T1090-002.md) — filters. Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure.
- [T1090.003 — Multi-hop Proxy](/mitre/techniques/T1090-003.md) — filters. Adversaries may chain together multiple proxies to disguise the source of malicious traffic.
- [T1090.004 — Domain Fronting](/mitre/techniques/T1090-004.md) — filters. Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through…
- [T1095 — Non-Application Layer Protocol](/mitre/techniques/T1095.md) — filters. Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network.
- [T1102 — Web Service](/mitre/techniques/T1102.md) — filters. Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system.
- [T1104 — Multi-Stage Channels](/mitre/techniques/T1104.md) — filters. Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions.
- [T1105 — Ingress Tool Transfer](/mitre/techniques/T1105.md) — filters. Adversaries may transfer tools or other files from an external system into a compromised environment.
- [T1132 — Data Encoding](/mitre/techniques/T1132.md) — filters. Adversaries may encode data to make the content of command and control traffic more difficult to detect.
- [T1197 — BITS Jobs](/mitre/techniques/T1197.md) — filters. Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks.
- [T1204.001 — Malicious Link](/mitre/techniques/T1204-001.md) — filters. An adversary may rely upon a user clicking a malicious link in order to gain execution.
- [T1219 — Remote Access Tools](/mitre/techniques/T1219.md) — filters. An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network.
- [T1567 — Exfiltration Over Web Service](/mitre/techniques/T1567.md) — filters. Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.
- [T1567.001 — Exfiltration to Code Repository](/mitre/techniques/T1567-001.md) — filters. Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel.
- [T1567.002 — Exfiltration to Cloud Storage](/mitre/techniques/T1567-002.md) — filters. Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel.
- [T1568 — Dynamic Resolution](/mitre/techniques/T1568.md) — filters. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.
- [T1571 — Non-Standard Port](/mitre/techniques/T1571.md) — filters. Adversaries may communicate using a protocol and port pairing that are typically not associated.
- [T1572 — Protocol Tunneling](/mitre/techniques/T1572.md) — filters. Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems.
- [T1573 — Encrypted Channel](/mitre/techniques/T1573.md) — filters. Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1573.001 — Symmetric Cryptography](/mitre/techniques/T1573-001.md) — filters. Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1573.002 — Asymmetric Cryptography](/mitre/techniques/T1573-002.md) — filters. Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
