# CAPEC-178 — Cross-Site Flashing

<a id="capec-178"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An attacker is able to trick the victim into executing a Flash document that passes commands or calls to a Flash player browser plugin, allowing the attacker to exploit native Flash functionality in the client browser. This attack pattern occurs where an attacker can provide a crafted link to a Flash document (SWF file) which, when followed, will cause additional malicious instructions to be execu

## Related CWE (1)

- [CWE-601 — URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Prerequisites

- The targeted Flash application must reference external URLs and the locations thus referenced must be controllable through parameters. The Flash application must fail to sanitize such parameters aga

## Skills required

- knowledge of Flash internals, parameters and remote referencing.:LEVEL:Medium

## Mitigations

- Implementation: Only allow known URL to be included as remote flash movies in a flash application
- Configuration: Properly configure the crossdomain.xml file to only include the known domains that should host remote flash movies.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
