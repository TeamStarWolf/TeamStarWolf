# D3FEND: Change Default Password

<a id="change-default-password"></a>

D3FEND tactic: Harden  
Digital artifacts: Password, User Account, OT Controller  

Changing the default password means replacing the factory-set credentials with a strong, unique password before the device is deployed, preventing unauthorized access.

## ATT&CK techniques countered (23)

- [T0812](https://attack.mitre.org/techniques/T0812): strengthens
- [T0848](https://attack.mitre.org/techniques/T0848): hardens
- [T0859](https://attack.mitre.org/techniques/T0859): strengthens
- [T1078: Valid Accounts](/mitre/techniques/T1078.md): strengthens. Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.001: Default Accounts](/mitre/techniques/T1078-001.md): strengthens. Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.002: Domain Accounts](/mitre/techniques/T1078-002.md): strengthens. Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.003: Local Accounts](/mitre/techniques/T1078-003.md): strengthens. Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1078.004: Cloud Accounts](/mitre/techniques/T1078-004.md): strengthens. Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
- [T1087.001: Local Account](/mitre/techniques/T1087-001.md): strengthens. Adversaries may attempt to get a listing of local system accounts.
- [T1087.002: Domain Account](/mitre/techniques/T1087-002.md): strengthens. Adversaries may attempt to get a listing of domain accounts.
- [T1087.004: Cloud Account](/mitre/techniques/T1087-004.md): strengthens. Adversaries may attempt to get a listing of cloud accounts.
- [T1098: Account Manipulation](/mitre/techniques/T1098.md): strengthens. Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.
- [T1098.002: Additional Email Delegate Permissions](/mitre/techniques/T1098-002.md): strengthens. Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.
- [T1098.003: Additional Cloud Roles](/mitre/techniques/T1098-003.md): strengthens. An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant.
- [T1110.001: Password Guessing](/mitre/techniques/T1110-001.md): strengthens. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.002: Password Cracking](/mitre/techniques/T1110-002.md): strengthens. Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): strengthens. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1136: Create Account](/mitre/techniques/T1136.md): strengthens. Adversaries may create an account to maintain access to victim systems.
- [T1136.001: Local Account](/mitre/techniques/T1136-001.md): strengthens. Adversaries may create a local account to maintain access to victim systems.
- [T1136.002: Domain Account](/mitre/techniques/T1136-002.md): strengthens. Adversaries may create a domain account to maintain access to victim systems.
- [T1136.003: Cloud Account](/mitre/techniques/T1136-003.md): strengthens. Adversaries may create a cloud account to maintain access to victim systems.
- [T1531: Account Access Removal](/mitre/techniques/T1531.md): strengthens. Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
- [T1548.005: Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md): strengthens. Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
