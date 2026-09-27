# CAPEC-103 — Clickjacking

<a id="capec-103"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary tricks a victim into unknowingly initiating some action in one system while interacting with the UI from a seemingly completely different, usually an adversary controlled or intended, system.

## Related CWE (1)

- [CWE-1021 — Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

## Prerequisites

- The victim is communicating with the target application via a web based UI and not a thick client
- The victim's browser security policies allow at least one of the following JavaScript, Flash, iFram

## Skills required

- Crafting the proper malicious site and luring the victim to this site are not trivial tasks.:LEVEL:High

## Mitigations

- If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.
- Turn off JavaScript, Flash and disable CSS.
- When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate t

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
