# CAPEC-492 — Regular Expression Exponential Blowup

<a id="capec-492"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary may execute an attack on a program that uses a poor Regular Expression(Regex) implementation by choosing input that results in an extreme situation for the Regex. A typical extreme situation operates at exponential time compared to the input size. This is due to most implementations using a Nondeterministic Finite Automaton(NFA) state machine to be built by the Regex algorithm since NFA allows backtracking and thus more complex regular expressions.

## Related CWE (2)

- [CWE-400 — Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) — The product does not properly control the allocation and maintenance of a limited resource.
- [CWE-1333 — Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) — The product uses a regular expression with a worst-case computational complexity that is inefficient and possibly exponential.

## Prerequisites

- This type of an attack requires the ability to identify hosts running a poorly implemented Regex, and the ability to send crafted input to exploit the regular expression.

## Mitigations

- Test custom written Regex with fuzzing to determine if the Regex is a poor one. Add timeouts to processes that handle the Regex logic. If an evil Regex is found rewrite it as a good Regex.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
