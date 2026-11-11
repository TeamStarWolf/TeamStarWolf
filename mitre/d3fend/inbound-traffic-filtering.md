# D3FEND: Inbound Traffic Filtering

<a id="inbound-traffic-filtering"></a>

D3FEND tactic: Isolate  
Digital artifacts: Inbound Network Traffic  

Restricting network traffic originating from untrusted networks destined towards a private host or enclave.

## ATT&CK techniques countered (9)

- [T0819: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819): filters
- [T0822: External Remote Services](https://attack.mitre.org/techniques/T0822): filters
- [T0865: Spearphishing Attachment](https://attack.mitre.org/techniques/T0865): filters
- [T1190: Exploit Public-Facing Application](/mitre/techniques/T1190.md): filters. Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.
- [T1498.001: Direct Network Flood](/mitre/techniques/T1498-001.md): filters. Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.
- [T1498.002: Reflection Amplification](/mitre/techniques/T1498-002.md): filters. Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target.
- [T1499.002: Service Exhaustion Flood](/mitre/techniques/T1499-002.md): filters. Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).
- [T1566.001: Spearphishing Attachment](/mitre/techniques/T1566-001.md): filters. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002: Spearphishing Link](/mitre/techniques/T1566-002.md): filters. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 9 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 9 of these techniques
- [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md), which also counters 9 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 9 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 9 of these techniques
- [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), which also counters 9 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md)
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
