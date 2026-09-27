# CAPEC-74 — Manipulating State

<a id="capec-74"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

The adversary modifies state information maintained by the target software or causes a state transition in hardware. If successful, the target will use this tainted state and execute in an unintended manner. State management is an important function within a software application. User state maintained by the application can include usernames, payment information, browsing history as well as application-specific contents such as items in a shopping cart. Manipulating user state can be employed by an adversary to elevate privilege, conduct fraudulent transactions or otherwise modify the flow of the application to derive certain benefits. If there is a hardware logic error in a finite state machine, the adversary can use this to put the system in an undefined state which could cause a denial of service or exposure of secure data.

## Related CWE (8)

- [CWE-372 — Incomplete Internal State Distinction](https://cwe.mitre.org/data/definitions/372.html) — The product does not properly determine which state it is in, causing it to assume it is in state X when in fact it is in state Y, causing it to perform incorrect operations in a security-relevant manner.
- [CWE-315 — Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html) — The product stores sensitive information in cleartext in a cookie.
- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html) — The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.
- [CWE-1245 — Improper Finite State Machines (FSMs) in Hardware Logic](https://cwe.mitre.org/data/definitions/1245.html) — Faulty finite state machines (FSMs) in the hardware logic allow an attacker to put the system in an undefined state, to cause a denial of service (DoS) or gain privileges on the victim's system.
- [CWE-1253 — Incorrect Selection of Fuse Values](https://cwe.mitre.org/data/definitions/1253.html) — The logic level used to set a system to a secure state relies on a fuse being unblown.
- [CWE-1265 — Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls](https://cwe.mitre.org/data/definitions/1265.html) — The product invokes code that is believed to be reentrant, but the code performs a call that unintentionally produces a nested invocation of the non-reentrant code.
- [CWE-1271 — Uninitialized Value on Reset for Registers Holding Security Settings](https://cwe.mitre.org/data/definitions/1271.html) — Security-critical logic is not set to a known value on reset.

## Prerequisites

- User state is maintained at least in some way in user-controllable locations, such as cookies or URL parameters.
- There is a faulty finite state machine in the hardware logic that can be exploited.

## Skills required

- [Medium] The adversary needs to have knowledge of state management as employed by the target application, and also the ability to manipulate the state in a meaningful way.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data
- Availability / Unreliable Execution

## Mitigations

- Do not rely solely on user-controllable locations, such as cookies or URL parameters, to maintain user state.
- Avoid sensitive information, such as usernames or authentication and authorization information, in user-controllable locations.
- Sensitive information that is part of the user state must be appropriately protected to ensure confidentiality and integrity at each request.
- All possible states must be handled by hardware finite state machines.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
