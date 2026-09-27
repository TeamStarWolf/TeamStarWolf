# D3FEND: Reverse Resolution IP Denylisting

<a id="reverse-resolution-ip-denylisting"></a>

**D3FEND tactic:** Isolate
**Digital artifacts:** Outbound Internet DNS Lookup Traffic

Blocking a reverse lookup based on the query's IP address value.

## ATT&CK techniques countered (2)

- [T1071.004 — DNS](/mitre/techniques/T1071-004.md) — blocks. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1568 — Dynamic Resolution](/mitre/techniques/T1568.md) — blocks. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
