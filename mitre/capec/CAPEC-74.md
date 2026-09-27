# CAPEC-74 — Manipulating State

<a id="capec-74"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

The adversary modifies state information maintained by the target software or causes a state transition in hardware. If successful, the target will use this tainted state and execute in an unintended manner. State management is an important function within a software application. User state maintained by the application can include usernames, payment information, browsing history as well as applic

## Related CWE (8)

- [CWE-372 — Incomplete Internal State Distinction](https://cwe.mitre.org/data/definitions/372.html)
- [CWE-315 — Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)
- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-1245 — Improper Finite State Machines (FSMs) in Hardware Logic](https://cwe.mitre.org/data/definitions/1245.html)
- [CWE-1253 — Incorrect Selection of Fuse Values](https://cwe.mitre.org/data/definitions/1253.html)
- [CWE-1265 — Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls](https://cwe.mitre.org/data/definitions/1265.html)
- [CWE-1271 — Uninitialized Value on Reset for Registers Holding Security Settings](https://cwe.mitre.org/data/definitions/1271.html)

## Prerequisites

- User state is maintained at least in some way in user-controllable locations, such as cookies or URL parameters.
- There is a faulty finite state machine in the hardware logic that can be exploited.:

## Skills required

- The adversary needs to have knowledge of state management as employed by the target application, and also the ability to manipulate the state

## Mitigations

- Do not rely solely on user-controllable locations, such as cookies or URL parameters, to maintain user state.
- Avoid sensitive information, such as usernames or authentication and authorization information, in user-controllable locations.
- Sensitiv

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
