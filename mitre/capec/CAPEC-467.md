# CAPEC-467 — Cross Site Identification

<a id="capec-467"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

An attacker harvests identifying information about a victim via an active session that the victim's browser has with a social networking site. A victim may have the social networking site open in one tab or perhaps is simply using the remember me feature to keep their session with the social networking site active. An attacker induces a payload to execute in the victim's browser that transparently

## Related CWE (2)

- [CWE-352 — Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) — The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.
- [CWE-359 — Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html) — The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent…

## Prerequisites

- The victim has an active session with the social networking site.

## Skills required

- An attacker should be able to create a payload and deliver it to the victim's browser.:LEVEL:High
- An attacker needs to know how to inte

## Mitigations

- Usage: Users should always explicitly log out from the social networking sites when done using them.
- Usage: Users should not open other tabs in the browser when using a social networking site.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
