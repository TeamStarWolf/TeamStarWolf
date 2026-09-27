# CAPEC-181 — Flash File Overlay

<a id="capec-181"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker creates a transparent overlay using flash in order to intercept user actions for the purpose of performing a clickjacking attack. In this technique, the Flash file provides a transparent overlay over HTML content. Because the Flash application is on top of the content, user actions, such as clicks, are caught by the Flash application rather than the underlying HTML. The action is then interpreted by the overlay to perform the actions the attacker wishes.

## Related CWE (1)

- [CWE-1021 — Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html) — The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.

## Prerequisites

- The victim must be tricked into navigating to the attackers' decoy site and performing the actions on the decoy page.
- The victim's browser must support invisible Flash overlays.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
