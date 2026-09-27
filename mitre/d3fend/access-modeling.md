# D3FEND: Access Modeling

<a id="access-modeling"></a>

**D3FEND tactic:** Model
**Digital artifacts:** Access Control Configuration, User Account

Access modeling captures and records the access permissions granted to identities (e.g., administrators, users, groups, systems) and optionally includes details on how these identities are stored, managed, and shared across systems.

## ATT&CK techniques countered (26)

- [T0812](https://attack.mitre.org/techniques/T0812) — maps
- [T0859](https://attack.mitre.org/techniques/T0859) — maps
- [T1078 — Valid Accounts](/mitre/techniques/T1078.md) — maps. Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.001 — Default Accounts](/mitre/techniques/T1078-001.md) — maps. Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.002 — Domain Accounts](/mitre/techniques/T1078-002.md) — maps. Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.003 — Local Accounts](/mitre/techniques/T1078-003.md) — maps. Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.004 — Cloud Accounts](/mitre/techniques/T1078-004.md) — maps. Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1087.001 — Local Account](/mitre/techniques/T1087-001.md) — maps. Adversaries may attempt to get a listing of local system accounts.
- [T1087.002 — Domain Account](/mitre/techniques/T1087-002.md) — maps. Adversaries may attempt to get a listing of domain accounts.
- [T1087.004 — Cloud Account](/mitre/techniques/T1087-004.md) — maps. Adversaries may attempt to get a listing of cloud accounts.
- [T1098 — Account Manipulation](/mitre/techniques/T1098.md) — maps. Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.
- [T1098.002 — Additional Email Delegate Permissions](/mitre/techniques/T1098-002.md) — maps. Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.
- [T1098.003 — Additional Cloud Roles](/mitre/techniques/T1098-003.md) — maps. An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant.
- [T1134.005 — SID-History Injection](/mitre/techniques/T1134-005.md) — maps. Adversaries may use SID-History Injection to escalate privileges and bypass access controls.
- [T1136 — Create Account](/mitre/techniques/T1136.md) — maps. Adversaries may create an account to maintain access to victim systems.
- [T1136.001 — Local Account](/mitre/techniques/T1136-001.md) — maps. Adversaries may create a local account to maintain access to victim systems.
- [T1136.002 — Domain Account](/mitre/techniques/T1136-002.md) — maps. Adversaries may create a domain account to maintain access to victim systems.
- [T1136.003 — Cloud Account](/mitre/techniques/T1136-003.md) — maps. Adversaries may create a cloud account to maintain access to victim systems.
- [T1222 — File and Directory Permissions Modification](/mitre/techniques/T1222.md) — maps. Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.
- [T1484 — Domain or Tenant Policy Modification](/mitre/techniques/T1484.md) — maps. Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments.
- [T1531 — Account Access Removal](/mitre/techniques/T1531.md) — maps. Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
- [T1548.001 — Setuid and Setgid](/mitre/techniques/T1548-001.md) — maps. An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context.
- [T1548.005 — Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md) — maps. Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.
- [T1552.006 — Group Policy Preferences](/mitre/techniques/T1552-006.md) — maps. Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP).
- [T1556.009 — Conditional Access Policies](/mitre/techniques/T1556-009.md) — maps. Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts.
- [T1615 — Group Policy Discovery](/mitre/techniques/T1615.md) — maps. Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or…

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
