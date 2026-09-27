# CAPEC-209 — XSS Using MIME Type Mismatch

<a id="capec-209"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the

## Related CWE (3)

[CWE-79](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-646](/CWE_REFERENCE.md)

**Prerequisites:** ::The victim must follow a crafted link that references a scripting file that is mis-typed as a non-executable file.::The victim's browser must detect the true type of a mis-labeled scripting file and


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
