# CAPEC-63: Cross-Site Scripting (XSS)

<a id="capec-63"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An adversary embeds malicious scripts in content that will be served to web browsers. The goal of the attack is for the target software, the client-side browser, to execute the script with the users' privilege level. An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute code and scripts. Web browsers, for example, have some simple security controls in place, but if a remote attacker is allowed to execute scripts (through injecting them in to user-generated content like bulletin boards) then these controls may be bypassed. Further, these attacks are very difficult for an end user to detect.

## Related CWE (2)

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html): The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- Target client software must be a client that allows scripting communication from remote hosts, such as a JavaScript-enabled Web Browser.

## Skills required

- [Low] To achieve a redirection and use of less trusted source, an attacker can simply place a script in bulletin board, blog, wiki, or other user-generated content site that are echoed back to other client machines.
- [High] Exploiting a client side vulnerability to inject malicious scripts into the browser's executable process.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data
- Confidentiality / Read Data

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Session tokens for specific host
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

## Related pages

- [CAPEC-85: AJAX Footprinting](/mitre/capec/CAPEC-85.md), also related to CWE-20 and CWE-79
- [CAPEC-209: XSS Using MIME Type Mismatch](/mitre/capec/CAPEC-209.md), also related to CWE-20 and CWE-79
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

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Instructure Canvas Breach and ShinyHunters Extortion of 2026: A Case Study](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md)
- [The Year 2000 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2000.md)
- [The Year 2005 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2005.md)
- [The Year 2006 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2006.md)
- [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md)
- [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2011 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2011.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
