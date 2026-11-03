# D3FEND: Reverse Resolution IP Denylisting

<a id="reverse-resolution-ip-denylisting"></a>

D3FEND tactic: Isolate  
Digital artifacts: Outbound Internet DNS Lookup Traffic  

Blocking a reverse lookup based on the query's IP address value.

## ATT&CK techniques countered (2)

- [T1071.004: DNS](/mitre/techniques/T1071-004.md): blocks. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1568: Dynamic Resolution](/mitre/techniques/T1568.md): blocks. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 2 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 2 of these techniques
- [DNS Allowlisting](/mitre/d3fend/dns-allowlisting.md), which also counters 2 of these techniques
- [DNS Denylisting](/mitre/d3fend/dns-denylisting.md), which also counters 2 of these techniques
- [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md), which also counters 2 of these techniques
- [Forward Resolution Domain Denylisting](/mitre/d3fend/forward-resolution-domain-denylisting.md), which also counters 2 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
