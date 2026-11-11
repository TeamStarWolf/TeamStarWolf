# CAPEC-650: Upload a Web Shell to a Web Server

<a id="capec-650"></a>

Abstraction: Detailed  
Typical severity: High  
Status: Draft  

By exploiting insufficient permissions, it is possible to upload a web shell to a web server in such a way that it can be executed remotely. This shell can have various capabilities, thereby acting as a "gateway" to the underlying web server. The shell might execute at the higher permission level of the web server, providing the ability the execute malicious code at elevated levels.

## Mapped ATT&CK techniques (1)

- [T1505.003: Web Shell](/mitre/techniques/T1505-003.md): Adversaries may backdoor web servers with web shells to establish persistent access to systems.

## Related CWE (2)

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.
- [CWE-553: Command Shell in Externally Accessible Directory](https://cwe.mitre.org/data/definitions/553.html): A possible shell file exists in /cgi-bin/ or other accessible directories.

## Prerequisites

- The web server is susceptible to one of the various web application exploits that allows for uploading a shell file.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Make sure your web server is up-to-date with all patches to protect against known vulnerabilities.
- Ensure that the file permissions in directories on the web server from which files can be execute is set to the "least privilege" settings, and that those directories contents is controlled by an allowlist.

## Related pages

- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-287
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-287
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287
- [CAPEC-114: Authentication Abuse](/mitre/capec/CAPEC-114.md), also related to CWE-287
- [CAPEC-115: Authentication Bypass](/mitre/capec/CAPEC-115.md), also related to CWE-287
- [CAPEC-151: Identity Spoofing](/mitre/capec/CAPEC-151.md), also related to CWE-287
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md)
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
