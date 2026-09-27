# CAPEC-498 — Probe iOS Screenshots

<a id="capec-498"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary examines screenshot images created by iOS in an attempt to obtain sensitive information. This attack targets temporary screenshots created by the underlying OS while the application remains open in the background.

## Related CWE (1)

[CWE-359](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires physical access to a device to either excavate the image files (potentially by leveraging a Jailbreak) or view the screenshots through the multitasking switcher (by d

**Mitigations:** ::To mitigate this type of an attack, an application that may display sensitive information should clear the screen contents before a screenshot is taken. This can be accomplished by setting the key window's hidden property to YES. This code to hide 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
