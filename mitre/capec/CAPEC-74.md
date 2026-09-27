# CAPEC-74 — Manipulating State

<a id="capec-74"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium

The adversary modifies state information maintained by the target software or causes a state transition in hardware. If successful, the target will use this tainted state and execute in an unintended manner. State management is an important function within a software application. User state maintained by the application can include usernames, payment information, browsing history as well as applic

## Related CWE (8)

[CWE-372](/CWE_REFERENCE.md) [CWE-315](/CWE_REFERENCE.md) [CWE-353](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md) [CWE-1245](/CWE_REFERENCE.md) [CWE-1253](/CWE_REFERENCE.md) [CWE-1265](/CWE_REFERENCE.md) [CWE-1271](/CWE_REFERENCE.md)

**Prerequisites:** ::User state is maintained at least in some way in user-controllable locations, such as cookies or URL parameters.::There is a faulty finite state machine in the hardware logic that can be exploited.:

**Skills required:** ::SKILL:The adversary needs to have knowledge of state management as employed by the target application, and also the ability to manipulate the state 

**Mitigations:** ::Do not rely solely on user-controllable locations, such as cookies or URL parameters, to maintain user state.::Avoid sensitive information, such as usernames or authentication and authorization information, in user-controllable locations.::Sensitiv


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
