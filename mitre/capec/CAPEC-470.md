# CAPEC-470 — Expanding Control over the Operating System from the Database

<a id="capec-470"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** 

An attacker is able to leverage access gained to the database to read / write data to the file system, compromise the operating system, create a tunnel for accessing the host machine, and use this access to potentially attack other machines on the same network as the database machine. Traditionally SQL injections attacks are viewed as a way to gain unauthorized read access to the data stored in th

## Related CWE (2)

[CWE-250](/CWE_REFERENCE.md) [CWE-89](/CWE_REFERENCE.md)

**Prerequisites:** ::A vulnerable DBMS is usedA SQL injection exists that gives an attacker access to the database or an attacker has access to the DBMS via other means::

**Skills required:** ::SKILL:Low level knowledge of the various facilities available in different DBMS systems for interacting with the file system and operating system:LE

**Mitigations:** ::Design: Follow the defensive programming practices needed to protect an application accessing the database from SQL injection::Configuration: Ensure that the DBMS is patched with the latest security patches::Design: Ensure that the DBMS login used 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
