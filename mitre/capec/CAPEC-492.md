# CAPEC-492: Regular Expression Exponential Blowup

<a id="capec-492"></a>

Abstraction: Standard  
Status: Draft  

An adversary may execute an attack on a program that uses a poor Regular Expression(Regex) implementation by choosing input that results in an extreme situation for the Regex. A typical extreme situation operates at exponential time compared to the input size. This is due to most implementations using a Nondeterministic Finite Automaton(NFA) state machine to be built by the Regex algorithm since NFA allows backtracking and thus more complex regular expressions.

## Related CWE (2)

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html): The product does not properly control the allocation and maintenance of a limited resource.
- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html): The product uses a regular expression with a worst-case computational complexity that is inefficient and possibly exponential.

## Prerequisites

- This type of an attack requires the ability to identify hosts running a poorly implemented Regex, and the ability to send crafted input to exploit the regular expression.

## Mitigations

- Test custom written Regex with fuzzing to determine if the Regex is a poor one. Add timeouts to processes that handle the Regex logic. If an evil Regex is found rewrite it as a good Regex.

## Related pages

- [CAPEC-147: XML Ping of the Death](/mitre/capec/CAPEC-147.md), also related to CWE-400
- [CAPEC-227: Sustained Client Engagement](/mitre/capec/CAPEC-227.md), also related to CWE-400
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
