# CAPEC-96 — Block Access to Libraries

<a id="capec-96"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An application typically makes calls to functions that are a part of libraries external to the application. These libraries may be part of the operating system or they may be third party libraries. It is possible that the application does not handle situations properly where access to these libraries has been blocked. Depending on the error handling within the application, blocked access to librar

## Related CWE (1)

- [CWE-589 — Call to Non-ubiquitous API](https://cwe.mitre.org/data/definitions/589.html)

## Prerequisites

- An application requires access to external libraries.
- An attacker has the privileges to block application access to external libraries.

## Skills required

- Knowledge of how to block access to libraries, as well as knowledge of how to leverage the resulting state of the application based on the fai

## Mitigations

- Ensure that application handles situations where access to APIs in external libraries is not available securely. If the application cannot continue its execution safely it should fail in a consistent and secure fashion.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
