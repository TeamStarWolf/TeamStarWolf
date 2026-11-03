# CAPEC-279: SOAP Manipulation

<a id="capec-279"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

Simple Object Access Protocol (SOAP) is used as a communication protocol between a client and server to invoke web services on the server. It is an XML-based protocol, and therefore suffers from many of the same shortcomings as other XML-based protocols. Adversaries can make use of these shortcomings and manipulate the content of SOAP paramters, leading to undesirable behavior on the server and allowing the adversary to carry out a number of further attacks.

## Related CWE (1)

- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being used when received from an upstream component, or before being sent to a downstream component.

## Prerequisites

- An application uses SOAP-based web service api.
- An application does not perform sufficient input validation to ensure that user-controllable data is safe for an XML parser.
- The targeted server either fails to verify that data in SOAP messages conforms to the appropriate XML schema, or it fails to correctly handle the complete range of data allowed by the schema.

## Consequences

- Availability / Resource Consumption
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-707
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-707
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-707
- [CAPEC-52: Embedding NULL Bytes](/mitre/capec/CAPEC-52.md), also related to CWE-707
- [CAPEC-53: Postfix, Null Terminate, and Backslash](/mitre/capec/CAPEC-53.md), also related to CWE-707
- [CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic](/mitre/capec/CAPEC-64.md), also related to CWE-707
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
