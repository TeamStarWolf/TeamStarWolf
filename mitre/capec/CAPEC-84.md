# CAPEC-84: XQuery Injection

<a id="capec-84"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

This attack utilizes XQuery to probe and attack server systems; in a similar manner that SQL Injection allows an attacker to exploit SQL calls to RDBMS, XQuery Injection uses improperly validated data that is passed to XQuery commands to traverse and execute commands that the XQuery routines have access to. XQuery injection can be used to enumerate elements on the victim's environment, inject commands to the local host, or execute queries to remote files and data sources.

## Related CWE (2)

- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being used when received from an upstream component, or before being sent to a downstream component.

## Prerequisites

- The XQL must execute unvalidated data

## Skills required

- [Low] Basic understanding of XQuery

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Design: Perform input allowlist validation on all XML input
- Implementation: Run xml parsing and query infrastructure with minimal privileges so that an attacker is limited in their ability to probe other system resources from XQL.

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-74 and CWE-707
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-74 and CWE-707
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-74 and CWE-707
- [CAPEC-52: Embedding NULL Bytes](/mitre/capec/CAPEC-52.md), also related to CWE-74 and CWE-707
- [CAPEC-53: Postfix, Null Terminate, and Backslash](/mitre/capec/CAPEC-53.md), also related to CWE-74 and CWE-707
- [CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic](/mitre/capec/CAPEC-64.md), also related to CWE-74 and CWE-707
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
