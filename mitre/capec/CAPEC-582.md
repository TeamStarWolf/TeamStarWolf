# CAPEC-582: Route Disabling

<a id="capec-582"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An adversary disables the network route between two targets. The goal is to completely sever the communications channel between two entities. This is often the result of a major error or the use of an "Internet kill switch" by those in control of critical infrastructure. This attack pattern differs from most other obstruction patterns by targeting the route itself, as opposed to the data passed over the route.

## Prerequisites

- The adversary requires knowledge of and access to network route.

## Consequences

- Availability / Other

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
