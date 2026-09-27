# CAPEC-464 — Evercookie

<a id="capec-464"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker creates a very persistent cookie that stays present even after the user thinks it has been removed. The cookie is stored on the victim's machine in over ten places. When the victim clears the cookie cache via traditional means inside the browser, that operation removes the cookie from certain places but not others. The malicious code then replicates the cookie from all of the places wh

## Mapped ATT&CK techniques (1)

- [T1606.001 — Web Cookies](/mitre/techniques/T1606-001.md)

## Related CWE (1)

- [CWE-359 — Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

## Prerequisites

- The victim's browser is not configured to reject all cookiesThe victim visits a website that serves the attackers' evercookie

## Mitigations

- Design: Browser's design needs to be changed to limit where cookies can be stored on the client side and provide an option to clear these cookies in all places, as well as another option to stop these cookies from being written in the first place.:

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
