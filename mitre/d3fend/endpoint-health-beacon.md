# D3FEND: Endpoint Health Beacon

<a id="endpoint-health-beacon"></a>

**D3FEND tactic:** Detect  
**Digital artifacts:** Network Node  

Monitoring the security status of an endpoint by sending periodic messages with health status, where absence of a response may indicate that the endpoint has been compromised.

## ATT&CK techniques countered (15)

- [T0807](https://attack.mitre.org/techniques/T0807) — monitors
- [T0809](https://attack.mitre.org/techniques/T0809) — monitors
- [T0816](https://attack.mitre.org/techniques/T0816) — monitors
- [T0848](https://attack.mitre.org/techniques/T0848) — monitors
- [T0857](https://attack.mitre.org/techniques/T0857) — monitors
- [T0864](https://attack.mitre.org/techniques/T0864) — monitors
- [T0866](https://attack.mitre.org/techniques/T0866) — monitors
- [T0867](https://attack.mitre.org/techniques/T0867) — monitors
- [T1114.002 — Remote Email Collection](/mitre/techniques/T1114-002.md) — monitors. Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information.
- [T1505.002 — Transport Agent](/mitre/techniques/T1505-002.md) — monitors. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1505.003 — Web Shell](/mitre/techniques/T1505-003.md) — monitors. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1562.013 — Disable or Modify Network Device Firewall](/mitre/techniques/T1562-013.md) — monitors. Adversaries may disable network device-based firewall mechanisms entirely or add, delete, or modify particular rules in order to bypass controls limiting network usage.
- [T1578.002 — Create Cloud Instance](/mitre/techniques/T1578-002.md) — monitors. An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses.
- [T1578.003 — Delete Cloud Instance](/mitre/techniques/T1578-003.md) — monitors. An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence.
- [T1578.004 — Revert Cloud Instance](/mitre/techniques/T1578-004.md) — monitors. An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
