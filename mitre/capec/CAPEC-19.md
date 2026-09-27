# CAPEC-19 — Embedding Scripts within Scripts

<a id="capec-19"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary leverages the capability to execute their own script by embedding it within other scripts that the target software is likely to execute due to programs' vulnerabilities that are brought on by allowing remote hosts to execute scripts.

## Mapped ATT&CK techniques (3)

- [T1027.009](/mitre/techniques/T1027-009.md)
- [T1546.004](/mitre/techniques/T1546-004.md)
- [T1546.016](/mitre/techniques/T1546-016.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Prerequisites:** ::Target software must be able to execute scripts, and also grant the adversary privilege to write/upload scripts.::

**Skills required:** ::SKILL:To load malicious script into open, e.g. world writable directory:LEVEL:Low::SKILL:Executing remote scripts on host and collecting output:LEVE

**Mitigations:** ::Use browser technologies that do not allow client side scripting.::Utilize strict type, character, and encoding enforcement.::Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
