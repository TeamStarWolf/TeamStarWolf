# CAPEC-611 — BitSquatting

<a id="capec-611"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low

An adversary registers a domain name one bit different than a trusted domain. A BitSquatting attack leverages random errors in memory to direct Internet traffic to adversary-controlled destinations. BitSquatting requires no exploitation or complicated reverse engineering, and is operating system and architecture agnostic. Experimental observations show that BitSquatting popular websites could redi

**Prerequisites:** ::An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.::

**Skills required:** ::SKILL:Adversaries must be able to register DNS hostnames/URL’s.:LEVEL:Low::

**Mitigations:** ::Authenticate all servers and perform redundant checks when using DNS hostnames.::When possible, use error-correcting (ECC) memory in local devices as non-ECC memory is significantly more vulnerable to faults.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
