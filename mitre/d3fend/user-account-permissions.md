# D3FEND: User Account Permissions

<a id="user-account-permissions"></a>

D3FEND tactic: Isolate  
Digital artifacts: User Account  

Restricting a user account's access to resources.

## ATT&CK techniques countered (19)

- [T0859: Valid Accounts](https://attack.mitre.org/techniques/T0859): restricts
- [T1078: Valid Accounts](/mitre/techniques/T1078.md): restricts. Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.001: Default Accounts](/mitre/techniques/T1078-001.md): restricts. Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.002: Domain Accounts](/mitre/techniques/T1078-002.md): restricts. Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.003: Local Accounts](/mitre/techniques/T1078-003.md): restricts. Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.004: Cloud Accounts](/mitre/techniques/T1078-004.md): restricts. Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1087.001: Local Account](/mitre/techniques/T1087-001.md): restricts. Adversaries may attempt to get a listing of local system accounts.
- [T1087.002: Domain Account](/mitre/techniques/T1087-002.md): restricts. Adversaries may attempt to get a listing of domain accounts.
- [T1087.004: Cloud Account](/mitre/techniques/T1087-004.md): restricts. Adversaries may attempt to get a listing of cloud accounts.
- [T1098: Account Manipulation](/mitre/techniques/T1098.md): restricts. Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.
- [T1098.002: Additional Email Delegate Permissions](/mitre/techniques/T1098-002.md): restricts. Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.
- [T1098.003: Additional Cloud Roles](/mitre/techniques/T1098-003.md): restricts. An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant.
- [T1136: Create Account](/mitre/techniques/T1136.md): restricts. Adversaries may create an account to maintain access to victim systems.
- [T1136.001: Local Account](/mitre/techniques/T1136-001.md): restricts. Adversaries may create a local account to maintain access to victim systems.
- [T1136.002: Domain Account](/mitre/techniques/T1136-002.md): restricts. Adversaries may create a domain account to maintain access to victim systems.
- [T1136.003: Cloud Account](/mitre/techniques/T1136-003.md): restricts. Adversaries may create a cloud account to maintain access to victim systems.
- [T1531: Account Access Removal](/mitre/techniques/T1531.md): restricts. Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
- [T1548.005: Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md): restricts. Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.
- [T1694.001: Default Credentials](https://attack.mitre.org/techniques/T1694/001): restricts (D3FEND maps the revoked predecessor T0812)

## Related pages

- [Access Modeling](/mitre/d3fend/access-modeling.md), which also counters 19 of these techniques
- [Account Locking](/mitre/d3fend/account-locking.md), which also counters 19 of these techniques
- [Agent Authentication](/mitre/d3fend/agent-authentication.md), which also counters 19 of these techniques
- [Change Default Password](/mitre/d3fend/change-default-password.md), which also counters 19 of these techniques
- [Restore User Account Access](/mitre/d3fend/restore-user-account-access.md), which also counters 19 of these techniques
- [Unlock Account](/mitre/d3fend/unlock-account.md), which also counters 19 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown](/case-studies/CYBERCRIME_FOUR_BOOKS.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record](/case-studies/CHANGE_HEALTHCARE_2024.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
