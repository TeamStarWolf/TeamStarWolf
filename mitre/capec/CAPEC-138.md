# CAPEC-138: Reflection Injection

<a id="capec-138"></a>

Abstraction: Standard  
Typical severity: Very High  
Status: Draft  

An adversary supplies a value to the target application which is then used by reflection methods to identify a class, method, or field. For example, in the Java programming language the reflection libraries permit an application to inspect, load, and invoke classes and their components by name. If an adversary can control the input into these methods including the name of the class/method/field or the parameters passed to methods, they can cause the targeted application to invoke incorrect methods, read random fields, or even to load and utilize malicious classes that the adversary created. This can lead to the application revealing sensitive information, returning incorrect results, or even having the adversary take control of the targeted application.

## Related CWE (1)

- [CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html): The product uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.

## Prerequisites

- The target application must utilize reflection libraries and allow users to directly control the parameters to these methods. If the adversary can host classes where the target can invoke them, more powerful variants of this attack are possible.
- The target application must accept a string as user input, fail to sanitize characters that have a special meaning in the parameter encoding, and insert the user-supplied string in an encoding which is then processed.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
