# D3FEND: Application Configuration Hardening

<a id="application-configuration-hardening"></a>

D3FEND tactic: Harden  
Digital artifacts: Application Configuration  

Modifying an application's configuration to reduce its attack surface.

## ATT&CK techniques countered (6)

- [T0858: Change Operating Mode](https://attack.mitre.org/techniques/T0858): hardens
- [T0868: Detect Operating Mode](https://attack.mitre.org/techniques/T0868): hardens
- [T1114.003: Email Forwarding Rule](/mitre/techniques/T1114-003.md): hardens. Adversaries may setup email forwarding rules to collect sensitive information.
- [T1564.008: Email Hiding Rules](/mitre/techniques/T1564-008.md): hardens. Adversaries may use email rules to hide inbound emails in a compromised user's mailbox.
- [T1685.001: Disable or Modify Windows Event Log](/mitre/techniques/T1685-001.md): hardens (D3FEND maps the revoked predecessor T1562.002). Adversaries may disable or modify the Windows Event Log to limit data that can be leveraged for detections and audits.
- [T1690: Prevent Command History Logging](/mitre/techniques/T1690.md): hardens (D3FEND maps the revoked predecessor T1562.003). Adversaries may impair command history logging to hide commands they run on a compromised system.

## Related pages

- [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), which also counters 6 of these techniques
- [Disable Remote Access](/mitre/d3fend/disable-remote-access.md), which also counters 6 of these techniques
- [Restore Configuration](/mitre/d3fend/restore-configuration.md), which also counters 6 of these techniques
- [Message Authentication](/mitre/d3fend/message-authentication.md), which also counters 2 of these techniques
- [Message Encryption](/mitre/d3fend/message-encryption.md), which also counters 2 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 2 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md)
- [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md)
- [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md)
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md)
- [ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
