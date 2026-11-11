# D3FEND: Disable Remote Access

<a id="disable-remote-access"></a>

D3FEND tactic: Harden  
Digital artifacts: Application Configuration  

Limiting access to a computing device which is not required through or from a non-organization-controlled network.

## ATT&CK techniques countered (6)

- [T0858: Change Operating Mode](https://attack.mitre.org/techniques/T0858): configures
- [T0868: Detect Operating Mode](https://attack.mitre.org/techniques/T0868): configures
- [T1114.003: Email Forwarding Rule](/mitre/techniques/T1114-003.md): configures. Adversaries may setup email forwarding rules to collect sensitive information.
- [T1564.008: Email Hiding Rules](/mitre/techniques/T1564-008.md): configures. Adversaries may use email rules to hide inbound emails in a compromised user's mailbox.
- [T1685.001: Disable or Modify Windows Event Log](/mitre/techniques/T1685-001.md): configures (D3FEND maps the revoked predecessor T1562.002). Adversaries may disable or modify the Windows Event Log to limit data that can be leveraged for detections and audits.
- [T1690: Prevent Command History Logging](/mitre/techniques/T1690.md): configures (D3FEND maps the revoked predecessor T1562.003). Adversaries may impair command history logging to hide commands they run on a compromised system.

## Related pages

- [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md), which also counters 6 of these techniques
- [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), which also counters 6 of these techniques
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

- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
