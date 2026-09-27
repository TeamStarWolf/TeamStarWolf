# CAPEC-63 — Cross-Site Scripting (XSS)

<a id="capec-63"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

An adversary embeds malicious scripts in content that will be served to web browsers. The goal of the attack is for the target software, the client-side browser, to execute the script with the users' privilege level. An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute code and scripts. Web browsers, for example, have some simple secur

## Related CWE (2)

[CWE-79](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::Target client software must be a client that allows scripting communication from remote hosts, such as a JavaScript-enabled Web Browser.::

**Skills required:** ::SKILL:To achieve a redirection and use of less trusted source, an attacker can simply place a script in bulletin board, blog, wiki, or other user-ge

**Mitigations:** ::Design: Use browser technologies that do not allow client side scripting.::Design: Utilize strict type, character, and encoding enforcement::Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
