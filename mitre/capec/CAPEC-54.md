# CAPEC-54 — Query System for Information

<a id="capec-54"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** High  
**Status:** Draft  

An adversary, aware of an application's location (and possibly authorized to use the application), probes an application's structure and evaluates its robustness by submitting requests and examining responses. Often, this is accomplished by sending variants of expected queries in the hope that these modified queries might return information beyond what the expected set of queries would provide.

## Related CWE (1)

- [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) — The product generates an error message that includes sensitive information about its environment, users, or associated data.

## Prerequisites

- This class of attacks does not strictly require authorized access to the application. As Attackers use this attack process to classify, map, and identify vulnerable aspects of an application, it simply requires hypotheses to be verified, interaction with the application, and time to conduct trial-and-error activities.

## Skills required

- [Medium] Although fuzzing parameters is not difficult, and often possible with automated fuzzers, interpreting the error conditions and modifying the parameters so as to move further in the process of mapping the application requires detailed knowledge of target platform, the languages and packages used as well as software design.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Application designers can construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are cataloged and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.
- Application designers can wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
