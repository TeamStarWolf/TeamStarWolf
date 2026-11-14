# D3FEND: Account Locking

<a id="account-locking"></a>

D3FEND tactic: Evict  
Digital artifacts: User Account  

The process of temporarily disabling user accounts on a system or domain.

## ATT&CK techniques countered (19)

- [T0859: Valid Accounts](https://attack.mitre.org/techniques/T0859): disables
- [T1078: Valid Accounts](/mitre/techniques/T1078.md): disables. Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.001: Default Accounts](/mitre/techniques/T1078-001.md): disables. Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.002: Domain Accounts](/mitre/techniques/T1078-002.md): disables. Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.003: Local Accounts](/mitre/techniques/T1078-003.md): disables. Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.004: Cloud Accounts](/mitre/techniques/T1078-004.md): disables. Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1087.001: Local Account](/mitre/techniques/T1087-001.md): disables. Adversaries may attempt to get a listing of local system accounts.
- [T1087.002: Domain Account](/mitre/techniques/T1087-002.md): disables. Adversaries may attempt to get a listing of domain accounts.
- [T1087.004: Cloud Account](/mitre/techniques/T1087-004.md): disables. Adversaries may attempt to get a listing of cloud accounts.
- [T1098: Account Manipulation](/mitre/techniques/T1098.md): disables. Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.
- [T1098.002: Additional Email Delegate Permissions](/mitre/techniques/T1098-002.md): disables. Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.
- [T1098.003: Additional Cloud Roles](/mitre/techniques/T1098-003.md): disables. An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant.
- [T1136: Create Account](/mitre/techniques/T1136.md): disables. Adversaries may create an account to maintain access to victim systems.
- [T1136.001: Local Account](/mitre/techniques/T1136-001.md): disables. Adversaries may create a local account to maintain access to victim systems.
- [T1136.002: Domain Account](/mitre/techniques/T1136-002.md): disables. Adversaries may create a domain account to maintain access to victim systems.
- [T1136.003: Cloud Account](/mitre/techniques/T1136-003.md): disables. Adversaries may create a cloud account to maintain access to victim systems.
- [T1531: Account Access Removal](/mitre/techniques/T1531.md): disables. Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
- [T1548.005: Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md): disables. Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.
- [T1694.001: Default Credentials](https://attack.mitre.org/techniques/T1694/001): disables (D3FEND maps the revoked predecessor T0812)

## Related pages

- [Access Modeling](/mitre/d3fend/access-modeling.md), which also counters 19 of these techniques
- [Agent Authentication](/mitre/d3fend/agent-authentication.md), which also counters 19 of these techniques
- [Change Default Password](/mitre/d3fend/change-default-password.md), which also counters 19 of these techniques
- [Restore User Account Access](/mitre/d3fend/restore-user-account-access.md), which also counters 19 of these techniques
- [Unlock Account](/mitre/d3fend/unlock-account.md), which also counters 19 of these techniques
- [User Account Permissions](/mitre/d3fend/user-account-permissions.md), which also counters 19 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md)
- [SSHole: The OpenSSH Authentication Bypass of November 2026 (CVE-2026-123158)](/case-studies/SSHOLE_CVE_2026_123158.md)
- [The CareCloud Medical-Records Breach of March 2026: A Case Study](/case-studies/CARECLOUD_BREACH_2026.md)
- [The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record](/case-studies/CHANGE_HEALTHCARE_2024.md)
- [The ConnectWise Cloud Backup Compromise of October 2026: A Case Study](/case-studies/CONNECTWISE_STORM_0940_2026.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)
- [The DentaQuest Health-Data Breach of May 2026: A Case Study](/case-studies/DENTAQUEST_BREACH_2026.md)
- [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Stryker Device-Wipe Attack of March 2026: A Case Study](/case-studies/STRYKER_HANDALA_WIPER_2026.md)
- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 2005 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2005.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
