# CAPEC-504 — Task Impersonation

<a id="capec-504"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary, through a previously installed malicious application, impersonates an expected or routine task in an attempt to steal sensitive information or leverage a user's privileges.

## Mapped ATT&CK techniques (1)

- [T1036.004 — Masquerade Task or Service](/mitre/techniques/T1036-004.md) — Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign.

## Related CWE (1)

- [CWE-1021 — Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html) — The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.

## Prerequisites

- The adversary must already have access to the target system via some means.
- A legitimate task must exist that an adversary can impersonate to glean credentials.
- The user's privileges allow them to

## Skills required

- Once an adversary has gained access to the target system, impersonating a task is trivial.:LEVEL:Low

## Mitigations

- The only known mitigation to this attack is to avoid installing the malicious application on the device. However, to impersonate a running task the malicious application does need the GET_TASKS permission to be able to query the task list, and bein

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
