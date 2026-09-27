# CAPEC-95 — WSDL Scanning

<a id="capec-95"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the WSDL interface made available by a web service. The attacker may scan the WSDL interface to reveal sensitive information about invocation patterns, underlying technology implementations and associated vulnerabilities. This type of probing is carried out to perform more serious attacks (e.g. parameter tampering, malicious content injection, command injection, etc.). WSDL fil

## Related CWE (1)

- [CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

## Prerequisites

- A client program connecting to a web service can read the WSDL to determine what functions are available on the server.
- The target host exposes vulnerable functions within its WSDL interface.

## Skills required

- This attack can be as simple as reading WSDL and starting sending invalid request.:LEVEL:Low
- This attack can be used to perform more so

## Mitigations

- It is important to protect WSDL file or provide limited access to it.
- Review the functions exposed by the WSDL interface (especially if you have used a tool to generate it). Make sure that none of them is vulnerable to injection.
- Ensure the WSDL

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
