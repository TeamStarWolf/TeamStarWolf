# CAPEC-529: Malware-Directed Internal Reconnaissance

<a id="capec-529"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: Medium  
Status: Stable  

Adversary uses malware or a similarly controlled application installed inside an organizational perimeter to gather information about the composition, configuration, and security mechanisms of a targeted application, system or network.

## Prerequisites

- The adversary must have internal, logical access to the target network and system.

## Skills required

- [Medium] The adversary must be able to obtain or develop, as well as place malicious software inside the target network/system.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Keep patches up to date by installing weekly or daily if possible.
- Identify programs that may be used to acquire peripheral information and block them by using a software restriction policy or tools that restrict program execution by using a process allowlist.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
