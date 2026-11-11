# CAPEC-664: Server Side Request Forgery

<a id="capec-664"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Stable  

An adversary exploits improper input validation by submitting maliciously crafted input to a target application running on a server, with the goal of forcing the server to make a request either to itself, to web services running in the server’s internal network, or to external third parties. If successful, the adversary’s request will be made with the server’s privilege level, bypassing its authentication controls. This ultimately allows the adversary to access sensitive data, execute commands on the server’s network, and make external requests with the stolen identity of the server. Server Side Request Forgery attacks differ from Cross Site Request Forgery attacks in that they target the server itself, whereas CSRF attacks exploit an insecure user authentication mechanism to perform unauthorized actions on the user's behalf.

## Related CWE (2)

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html): The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- Server must be running a web application that processes HTTP requests.

## Skills required

- [Medium] The adversary will have to detect the vulnerability through an intermediary service or specify maliciously crafted URLs and analyze the server response.
- [High] The adversary will be required to access internal resources, extract information, or leverage the services running on the server to perform unauthorized actions such as traversing the local network or routing a reflected TCP DDoS through them.

## Consequences

- Integrity, Confidentiality, Availability / Modify Data
- Confidentiality / Read Data
- Availability / Resource Consumption

## Mitigations

- Handling incoming requests securely is the first line of action to mitigate this vulnerability. This can be done through URL validation.
- Further down the process flow, examining the response and verifying that it is as expected before sending would be another way to secure the server.
- Allowlist the DNS name or IP address of every service the web application is required to access is another effective security measure. This ensures the server cannot make external requests to arbitrary services.
- Requiring authentication for local services adds another layer of security between the adversary and internal services running on the server. By enforcing local authentication, an adversary will not gain access to all internal services only with access to the server.
- Enforce the usage of relevant URL schemas. By limiting requests be made only through HTTP or HTTPS, for example, attacks made through insecure schemas such as file://, ftp://, etc. can be prevented.

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-20
- [CAPEC-8: Buffer Overflow in an API Call](/mitre/capec/CAPEC-8.md), also related to CWE-20
- [CAPEC-9: Buffer Overflow in Local Command-Line Utilities](/mitre/capec/CAPEC-9.md), also related to CWE-20
- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-20
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-20
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
