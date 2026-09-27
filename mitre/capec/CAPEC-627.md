# CAPEC-627 — Counterfeit GPS Signals

<a id="capec-627"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An adversary attempts to deceive a GPS receiver by broadcasting counterfeit GPS signals, structured to resemble a set of normal GPS signals. These spoofed signals may be structured in such a way as to cause the receiver to estimate its position to be somewhere other than where it actually is, or to be located where it is but at a different time, as determined by the adversary.

**Prerequisites:** ::The target must be relying on valid GPS signal to perform critical operations.::

**Skills required:** ::SKILL:The ability to spoof GPS signals is not trival.:LEVEL:High::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
