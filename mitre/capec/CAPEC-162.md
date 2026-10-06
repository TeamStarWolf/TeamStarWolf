# CAPEC-162: Manipulating Hidden Fields

<a id="capec-162"></a>

Abstraction: Detailed  
Typical severity: High  
Status: Draft  

An adversary exploits a weakness in the server's trust of client-side processing by modifying data on the client-side, such as price information, and then submitting this data to the server, which processes the modified data. For example, eShoplifting is a data manipulation attack against an on-line merchant during a purchasing transaction. The manipulation of price, discount or quantity fields in the transaction message allows the adversary to acquire items at a lower cost than the merchant intended. The adversary performs a normal purchasing transaction but edits hidden fields within the HTML form response that store price or other information to give themselves a better deal. The merchant then uses the modified pricing information in calculating the cost of the selected items.

## Related CWE (1)

- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html): The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

## Prerequisites

- The targeted site must contain hidden fields to be modified.
- The targeted site must not validate the hidden fields with backend processing.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
