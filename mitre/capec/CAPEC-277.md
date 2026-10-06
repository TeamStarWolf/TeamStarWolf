# CAPEC-277: Data Interchange Protocol Manipulation

<a id="capec-277"></a>

Abstraction: Standard  
Status: Draft  

Data Interchange Protocols are used to transmit structured data between entities. These protocols are often specific to a particular domain (B2B: purchase orders, invoices, transport logistics and waybills, medical records). They are often, but not always, XML-based. Subverting the protocol can allow an adversary to impersonate others, discover sensitive information, control the outcome of a session, or perform other attacks. This type of attack targets invalid assumptions that may be inherent in implementers of the protocol, incorrect implementations of the protocol, or vulnerabilities in the protocol itself.

## Related CWE (1)

- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream component.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
