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

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md)
- [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md)
- [Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown](/case-studies/CYBERCRIME_FOUR_BOOKS.md)
- [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md)
- [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md)
- [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md)
- [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md)
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md)
- [ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md)
- [Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study](/case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md)
- [The ATF Major Incident of 2026: A Case Study](/case-studies/ATF_MAJOR_INCIDENT_2026.md)
- [The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md)
- [The Boston Scientific Network Outage of August 2026: A Case Study](/case-studies/BOSTON_SCIENTIFIC_ATTACK_2026.md)
- [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md)
- [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md)
- [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md)
- [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md)
- [The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/CPANEL_WHM_CVE_2026_41940.md)
- [The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study](/case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md)
- [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md)
- [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md)
- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)
- [The Year 1999 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1999.md)
- [The Year 2000 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2000.md)
- [The Year 2001 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2001.md)
- [The Year 2002 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2002.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)
- [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md)
- [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)
- [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
