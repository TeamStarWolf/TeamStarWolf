# CAPEC-593: Session Hijacking

<a id="capec-593"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Stable  

This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The adversary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

## Mapped ATT&CK techniques (3)

- [T1185: Browser Session Hijacking](/mitre/techniques/T1185.md): Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1563: Remote Service Session Hijacking](/mitre/techniques/T1563.md): Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.

## Related CWE (1)

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Prerequisites

- An application that leverages sessions to perform authentication.

## Skills required

- [Low] Exploiting a poorly protected identity token is a well understood attack with many helpful resources available.

## Consequences

- Confidentiality, Integrity, Availability / Gain Privileges

## Mitigations

- Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

## Related pages

- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-287
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-287
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287
- [CAPEC-114: Authentication Abuse](/mitre/capec/CAPEC-114.md), also related to CWE-287
- [CAPEC-115: Authentication Bypass](/mitre/capec/CAPEC-115.md), also related to CWE-287
- [CAPEC-151: Identity Spoofing](/mitre/capec/CAPEC-151.md), also related to CWE-287
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md)
- [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Binance Hot-Wallet Theft of October 2026: A Case Study](/case-studies/BINANCE_HEIST_2026.md)
- [The Instructure Canvas Breach and ShinyHunters Extortion of 2026: A Case Study](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
