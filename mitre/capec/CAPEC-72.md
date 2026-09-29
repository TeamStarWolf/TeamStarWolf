# CAPEC-72 — URL Encoding

<a id="capec-72"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the encoding of the URL. An adversary can take advantage of the multiple way of encoding an URL and abuse the interpretation of the URL.

## Related CWE (6)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html) — The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-177 — Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html) — The product does not properly handle when all or part of an input has been URL encoded.
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html) — The product does not properly encode or decode the data, resulting in unexpected values.
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html) — The product allows user input to control or influence paths or file names that are used in filesystem operations.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- The application should accepts and decodes URL input.
- The application performs insufficient filtering/canonicalization on the URLs.

## Skills required

- [Low] An adversary can try special characters in the URL and bypass the URL validation.
- [Medium] The adversary may write a script to defeat the input filtering mechanism.

## Consequences

- Confidentiality / Read Data
- Availability / Resource Consumption
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Refer to the RFCs to safely decode URL.
- Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive.
- There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).
- Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test your decoding process against malicious input.
- Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. (See related guideline section)
- When client input is required from web-based forms, avoid using the "GET" method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the "POST method whenever possible.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
