# CAPEC-48 — Passing Local Filenames to Functions That Expect a URL

<a id="capec-48"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack relies on client side code to access local files and resources instead of URLs. When the client browser is expecting a URL string, but instead receives a request for a local file, that execution is likely to occur in the browser process space with the browser's authority to local files. The attacker can send the results of this request to the local files out to a site that they control

## Related CWE (2)

- [CWE-241 — Improper Handling of Unexpected Data Type](https://cwe.mitre.org/data/definitions/241.html)
- [CWE-706 — Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

## Prerequisites

- The victim's software must not differentiate between the location and type of reference passed the client software, e.g. browser

## Skills required

- Attacker identifies known local files to exploit:LEVEL:Medium

## Mitigations

- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Ensure all configuration files and resource are either removed or protected when promoting code into productio

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
