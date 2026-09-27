# CAPEC-215 — Fuzzing for application mapping

<a id="capec-215"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Draft  

An attacker sends random, malformed, or otherwise unexpected messages to a target application and observes the application's log or error messages returned. The attacker does not initially know how a target will respond to individual messages but by attempting a large number of message variants they may find a variant that trigger's desired behavior. In this attack, the purpose of the fuzzing is to observe the application's log and error messages, although fuzzing a target can also sometimes cause the target to enter an unstable state, causing a crash.

## Related CWE (2)

- [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) — The product generates an error message that includes sensitive information about its environment, users, or associated data.
- [CWE-532 — Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) — The product writes sensitive information to a log file.

## Prerequisites

- The target application must fail to sanitize incoming messages adequately before processing.

## Skills required

- [Medium] Although fuzzing parameters is not difficult, and often possible with automated fuzzing tools, interpreting the error conditions and modifying the parameters so as to move further in the process of mapping the application requires detailed knowledge of target platform, the languages and packages used as well as software design.

## Consequences

- Confidentiality / Other

## Mitigations

- Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.
- Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.
- Implementation: Obfuscate server fields of HTTP response.
- Implementation: Hide inner ordering of HTTP response header.
- Implementation: Customizing HTTP error codes such as 404 or 500.
- Implementation: Hide HTTP response header software information filed.
- Implementation: Hide cookie's software information filed.
- Implementation: Obfuscate database type in Database API's error message.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
