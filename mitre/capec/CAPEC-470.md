# CAPEC-470 — Expanding Control over the Operating System from the Database

<a id="capec-470"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Status:** Draft  

An attacker is able to leverage access gained to the database to read / write data to the file system, compromise the operating system, create a tunnel for accessing the host machine, and use this access to potentially attack other machines on the same network as the database machine. Traditionally SQL injections attacks are viewed as a way to gain unauthorized read access to the data stored in the database, modify the data in the database, delete the data, etc. However, almost every data base management system (DBMS) system includes facilities that if compromised allow an attacker complete access to the file system, operating system, and full access to the host running the database. The attacker can then use this privileged access to launch subsequent attacks. These facilities include dropping into a command shell, creating user defined functions that can call system level libraries present on the host machine, stored procedures, etc.

## Related CWE (2)

- [CWE-250 — Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) — The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.
- [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) — The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended…

## Prerequisites

- A vulnerable DBMS is usedA SQL injection exists that gives an attacker access to the database or an attacker has access to the DBMS via other means

## Skills required

- [High] Low level knowledge of the various facilities available in different DBMS systems for interacting with the file system and operating system

## Mitigations

- Design: Follow the defensive programming practices needed to protect an application accessing the database from SQL injection
- Configuration: Ensure that the DBMS is patched with the latest security patches
- Design: Ensure that the DBMS login used by the application has the lowest possible level of privileges in the DBMS
- Design: Ensure that DBMS runs with the lowest possible level of privileges on the host machine and that it runs as a separate user
- Usage: Do not use the DBMS machine for anything else other than the database
- Usage: Do not place any trust in the database host on the internal network. Authenticate and validate all network activity originating from the database host.
- Usage: Use an intrusion detection system to monitor network connections and logs on the database host.
- Implementation: Remove / disable all unneeded / unused functions of the DBMS system that may allow an attacker to elevate privileges if compromised

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
