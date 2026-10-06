# CAPEC-190: Reverse Engineer an Executable to Expose Assumed Hidden Functionality

<a id="capec-190"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An attacker analyzes a binary file or executable for the purpose of discovering the structure, function, and possibly source-code of the file by using a variety of analysis techniques to effectively determine how the software functions and operates. This type of analysis is also referred to as Reverse Code Engineering, as techniques exist for extracting source code from an executable. Several techniques are often employed for this purpose, both black box and white box. The use of computer bus analyzers and packet sniffers allows the binary to be studied at a level of interactions with its computing environment, such as a host OS, inter-process communication, and/or network communication. This type of analysis falls into the 'black box' category because it involves behavioral analysis of the software without reference to source code, object code, or protocol specifications.

## Related CWE (1)

- [CWE-912: Hidden Functionality](https://cwe.mitre.org/data/definitions/912.html): The product contains functionality that is not documented, not part of the specification, and not accessible through an interface or command sequence that is obvious to the product's users or administrators.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
