# CAPEC-568 — Capture Credentials via Keylogger

<a id="capec-568"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Draft  

An adversary deploys a keylogger in an effort to obtain credentials directly from a system's user. After capturing all the keystrokes made by a user, the adversary can analyze the data and determine which string are likely to be passwords or other credential related information.

## Mapped ATT&CK techniques (1)

- [T1056.001 — Keylogging](/mitre/techniques/T1056-001.md) — Adversaries may log user keystrokes to intercept credentials as the user types them.

## Prerequisites

- The ability to install the keylogger, either in person or remote.

## Mitigations

- Strong physical security can help reduce the ability of an adversary to install a keylogger.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
