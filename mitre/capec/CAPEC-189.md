# CAPEC-189: Black Box Reverse Engineering

<a id="capec-189"></a>

Abstraction: Standard  
Typical severity: Low  
Status: Draft  

An adversary discovers the structure, function, and composition of a type of computer software through black box analysis techniques. 'Black Box' methods involve interacting with the software indirectly, in the absence of direct access to the executable object. Such analysis typically involves interacting with the software at the boundaries of where the software interfaces with a larger execution environment, such as input-output vectors, libraries, or APIs. Black Box Reverse Engineering also refers to gathering physical side effects of a hardware device, such as electromagnetic radiation or sounds.

## Related CWE (3)

- [CWE-203: Observable Discrepancy](https://cwe.mitre.org/data/definitions/203.html): The product behaves differently or sends different responses under different circumstances in a way that is observable to an unauthorized actor.
- [CWE-1255: Comparison Logic is Vulnerable to Power Side-Channel Attacks](https://cwe.mitre.org/data/definitions/1255.html): A device's real time power consumption may be monitored during security token evaluation and the information gleaned may be used to determine the value of the reference token.
- [CWE-1300: Improper Protection of Physical Side Channels](https://cwe.mitre.org/data/definitions/1300.html): The device does not contain sufficient protection mechanisms to prevent physical side channels from exposing sensitive information due to patterns in physically observable phenomena such as variations in power consumption, electromagnetic emissions (EME), or acoustic emissions.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
