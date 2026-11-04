# D3FEND: Forward Resolution Domain Denylisting

<a id="forward-resolution-domain-denylisting"></a>

D3FEND tactic: Isolate  
Digital artifacts: Outbound Internet DNS Lookup Traffic  

Blocking a lookup based on the query's domain name value.

## ATT&CK techniques countered (2)

- [T1071.004: DNS](/mitre/techniques/T1071-004.md): blocks. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1568: Dynamic Resolution](/mitre/techniques/T1568.md): blocks. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 2 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 2 of these techniques
- [DNS Allowlisting](/mitre/d3fend/dns-allowlisting.md), which also counters 2 of these techniques
- [DNS Denylisting](/mitre/d3fend/dns-denylisting.md), which also counters 2 of these techniques
- [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md), which also counters 2 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 2 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
