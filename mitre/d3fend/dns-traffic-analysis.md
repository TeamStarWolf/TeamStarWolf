# D3FEND: DNS Traffic Analysis

<a id="dns-traffic-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: DNS Lookup, Outbound Internet DNS Lookup Traffic  

Analysis of domain name metadata, including name and DNS records, to determine whether the domain is likely to resolve to an undesirable host.

## ATT&CK techniques countered (4)

- [T0842: Network Sniffing](https://attack.mitre.org/techniques/T0842): may-contain
- [T1040: Network Sniffing](/mitre/techniques/T1040.md): may-contain. Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.
- [T1071.004: DNS](/mitre/techniques/T1071-004.md): analyzes. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1568: Dynamic Resolution](/mitre/techniques/T1568.md): analyzes. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 3 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 3 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 3 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 3 of these techniques
- [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), which also counters 3 of these techniques
- [Per Host Download-Upload Ratio Analysis](/mitre/d3fend/per-host-download-upload-ratio-analysis.md), which also counters 3 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md)
- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
