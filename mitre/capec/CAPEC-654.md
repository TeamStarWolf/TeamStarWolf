# CAPEC-654 — Credential Prompt Impersonation

<a id="capec-654"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary, through a previously installed malicious application, impersonates a credential prompt in an attempt to steal a user's credentials.

## Mapped ATT&CK techniques (2)

- [T1056 — Input Capture](/mitre/techniques/T1056.md) — Adversaries may use methods of capturing user input to obtain credentials or collect information.
- [T1548.004 — Elevated Execution with Prompt](/mitre/techniques/T1548-004.md) — Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials.

## Related CWE (1)

- [CWE-1021 — Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html) — The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.

## Prerequisites

- The adversary must already have access to the target system via some means.
- A legitimate task must exist that an adversary can impersonate to glean credentials.

## Skills required

- [Low] Once an adversary has gained access to the target system, impersonating a credential prompt is not difficult.

## Consequences

- Access Control, Authentication / Gain Privileges

## Mitigations

- The only known mitigation to this attack is to avoid installing the malicious application on the device. However, to impersonate a running task the malicious application does need the GET_TASKS permission to be able to query the task list, and being suspicious of applications with that permission can help.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
