# CAPEC-584 — BGP Route Disabling

<a id="capec-584"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary suppresses the Border Gateway Protocol (BGP) advertisement for a route so as to render the underlying network inaccessible. The BGP protocol helps traffic move throughout the Internet by selecting the most efficient route between Autonomous Systems (AS), or routing domains. BGP is the basis for interdomain routing infrastructure, providing connections between these ASs. By suppressing

**Prerequisites:** ::The adversary must have control of a router that can modify, drop, or introduce spoofed BGP updates.The adversary can convince::

**Mitigations:** ::Implement Ingress filters to check the validity of received routes. However, this relies on the accuracy of Internet Routing Registries (IRRs) databases which are often not well-maintained.::Implement Secure BGP (S-BGP protocol), which improves aut


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
