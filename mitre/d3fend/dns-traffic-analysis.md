# D3FEND: DNS Traffic Analysis

<a id="dns-traffic-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: DNS Lookup, Outbound Internet DNS Lookup Traffic  

Analysis of domain name metadata, including name and DNS records, to determine whether the domain is likely to resolve to an undesirable host.

## ATT&CK techniques countered (4)

- [T0842](https://attack.mitre.org/techniques/T0842): may-contain
- [T1040: Network Sniffing](/mitre/techniques/T1040.md): may-contain. Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.
- [T1071.004: DNS](/mitre/techniques/T1071-004.md): analyzes. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1568: Dynamic Resolution](/mitre/techniques/T1568.md): analyzes. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
