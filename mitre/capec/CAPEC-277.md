# CAPEC-277: Data Interchange Protocol Manipulation

<a id="capec-277"></a>

Abstraction: Standard  
Status: Draft  

Data Interchange Protocols are used to transmit structured data between entities. These protocols are often specific to a particular domain (B2B: purchase orders, invoices, transport logistics and waybills, medical records). They are often, but not always, XML-based. Subverting the protocol can allow an adversary to impersonate others, discover sensitive information, control the outcome of a session, or perform other attacks. This type of attack targets invalid assumptions that may be inherent in implementers of the protocol, incorrect implementations of the protocol, or vulnerabilities in the protocol itself.

## Related CWE (1)

- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being used when received from an upstream component, or before being sent to a downstream component.

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

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
