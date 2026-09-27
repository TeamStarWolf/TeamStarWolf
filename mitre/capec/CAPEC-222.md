# CAPEC-222 — iFrame Overlay

<a id="capec-222"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

In an iFrame overlay attack the victim is tricked into unknowingly initiating some action in one system while interacting with the UI from seemingly completely different system.

## Related CWE (1)

- [CWE-1021 — Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

## Prerequisites

- The victim is communicating with the target application via a web based UI and not a thick client. The victim's browser security policies allow iFrames. The victim uses a modern browser that support

## Skills required

- Crafting the proper malicious site and luring the victim to this site is not a trivial task.:LEVEL:High

## Mitigations

- Configuration: Disable iFrames in the Web browser.
- Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with t

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
