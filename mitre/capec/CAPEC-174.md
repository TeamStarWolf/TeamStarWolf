# CAPEC-174 — Flash Parameter Injection

<a id="capec-174"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

An adversary takes advantage of improper data validation to inject malicious global parameters into a Flash file embedded within an HTML document. Flash files can leverage user-submitted data to configure the Flash document and access the embedding HTML document.

## Related CWE (1)

- [CWE-88 — Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html) — The product constructs a string for a command to be executed by a separate component in another control sphere, but it does not properly delimit the intended arguments, options, or switches within that command string.

## Skills required

- The adversary need inject values into the global parameters to the Flash file and understand the parent HTML document DOM structure. The adver

## Mitigations

- User input must be sanitized according to context before reflected back to the user. The JavaScript function 'encodeURI' is not always sufficient for sanitizing input intended for global Flash parameters. Extreme caution should be taken when saving

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
