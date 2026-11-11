# CAPEC-209: XSS Using MIME Type Mismatch

<a id="capec-209"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary's script may run on the target unsanitized, possibly revealing the victim's cookies or executing arbitrary script in their browser.

## Related CWE (3)

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html): The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-646: Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html): The product allows a file to be uploaded, but it relies on the file name or extension of the file to determine the appropriate behaviors.

## Prerequisites

- The victim must follow a crafted link that references a scripting file that is mis-typed as a non-executable file.
- The victim's browser must detect the true type of a mis-labeled scripting file and invoke the appropriate script interpreter without first performing filtering on the content.

## Related pages

- [CAPEC-63: Cross-Site Scripting (XSS)](/mitre/capec/CAPEC-63.md), also related to CWE-20 and CWE-79
- [CAPEC-85: AJAX Footprinting](/mitre/capec/CAPEC-85.md), also related to CWE-20 and CWE-79
- [CAPEC-588: DOM-Based XSS](/mitre/capec/CAPEC-588.md), also related to CWE-20 and CWE-79
- [CAPEC-591: Reflected XSS](/mitre/capec/CAPEC-591.md), also related to CWE-79
- [CAPEC-592: Stored XSS](/mitre/capec/CAPEC-592.md), also related to CWE-79
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
