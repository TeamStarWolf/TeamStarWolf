# D3FEND: Session Termination

<a id="session-termination"></a>

**D3FEND tactic:** Evict
**Digital artifacts:** Session

Forcefully end all active sessions associated with compromised accounts or devices.

## ATT&CK techniques countered (10)

- [T0807](https://attack.mitre.org/techniques/T0807) — deletes
- [T0822](https://attack.mitre.org/techniques/T0822) — deletes
- [T1021.001 — Remote Desktop Protocol](/mitre/techniques/T1021-001.md) — deletes. Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).
- [T1021.004 — SSH](/mitre/techniques/T1021-004.md) — deletes. Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH).
- [T1133 — External Remote Services](/mitre/techniques/T1133.md) — deletes. Adversaries may leverage external-facing remote services to initially access and/or persist within a network.
- [T1134.003 — Make and Impersonate Token](/mitre/techniques/T1134-003.md) — deletes. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1199 — Trusted Relationship](/mitre/techniques/T1199.md) — deletes. Adversaries may breach or otherwise leverage organizations who have access to intended victims.
- [T1563 — Remote Service Session Hijacking](/mitre/techniques/T1563.md) — deletes. Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.
- [T1563.001 — SSH Hijacking](/mitre/techniques/T1563-001.md) — deletes. Adversaries may hijack a legitimate user's SSH session to move laterally within an environment.
- [T1563.002 — RDP Hijacking](/mitre/techniques/T1563-002.md) — deletes. Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
