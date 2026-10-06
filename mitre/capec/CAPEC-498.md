# CAPEC-498: Probe iOS Screenshots

<a id="capec-498"></a>

Abstraction: Detailed  
Status: Draft  

An adversary examines screenshot images created by iOS in an attempt to obtain sensitive information. This attack targets temporary screenshots created by the underlying OS while the application remains open in the background.

## Related CWE (1)

- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html): The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent of the person about whom the information is collected.

## Prerequisites

- This type of an attack requires physical access to a device to either excavate the image files (potentially by leveraging a Jailbreak) or view the screenshots through the multitasking switcher (by double tapping the home button on the device).

## Mitigations

- To mitigate this type of an attack, an application that may display sensitive information should clear the screen contents before a screenshot is taken. This can be accomplished by setting the key window's hidden property to YES. This code to hide the contents should be placed in both the applicationWillResignActive() and applicationDidEnterBackground() methods.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
