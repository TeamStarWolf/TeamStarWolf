# CAPEC-2: Inducing Account Lockout

<a id="capec-2"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An attacker leverages the security functionality of the system aimed at thwarting potential attacks to launch a denial of service attack against a legitimate system user. Many systems, for instance, implement a password throttling mechanism that locks an account after a certain number of incorrect log in attempts. An attacker can leverage this throttling mechanism to lock a legitimate user out of their own account. The weakness that is being leveraged by an attacker is the very security feature that has been put in place to counteract attacks.

## Mapped ATT&CK techniques (1)

- [T1531: Account Access Removal](/mitre/techniques/T1531.md): Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.

## Related CWE (1)

- [CWE-645: Overly Restrictive Account Lockout Mechanism](https://cwe.mitre.org/data/definitions/645.html): The product contains an account lockout protection mechanism, but the mechanism is too restrictive and can be triggered too easily, which allows attackers to deny service to legitimate users by causing their accounts to be locked out.

## Prerequisites

- The system has a lockout mechanism.
- An attacker must be able to reproduce behavior that would result in an account being locked.

## Skills required

- [Low] No programming skills or computer knowledge is needed. An attacker can easily use this attack pattern following the Execution Flow above.

## Consequences

- Availability / Resource Consumption

## Mitigations

- Implement intelligent password throttling mechanisms such as those which take IP address into account, in addition to the login name.
- When implementing security features, consider how they can be misused and made to turn on themselves.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
