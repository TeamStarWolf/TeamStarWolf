# CAPEC-592 — Stored XSS

<a id="capec-592"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary utilizes a form of Cross-site Scripting (XSS) where a malicious script is persistently "stored" within the data storage of a vulnerable web application as valid input.

## Related CWE (1)

- [CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) — The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

## Prerequisites

- An application that leverages a client-side web browser with scripting enabled.
- An application that fails to adequately sanitize or encode untrusted input.
- An application that stores information provided by the user in data storage of some kind.

## Skills required

- [Medium] Requires the ability to write scripts of varying complexity and to inject them through user controlled fields within the application.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Authorization, Access Control / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data

## Mitigations

- Use browser technologies that do not allow client-side scripting.
- Utilize strict type, character, and encoding enforcement.
- Ensure that all user-supplied input is validated before being stored.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
