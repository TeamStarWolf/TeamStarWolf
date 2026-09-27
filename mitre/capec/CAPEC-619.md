# CAPEC-619 — Signal Strength Tracking

<a id="capec-619"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

In this attack scenario, the attacker passively monitors the signal strength of the target’s cellular RF signal or WiFi RF signal and uses the strength of the signal (with directional antennas and/or from multiple listening points at once) to identify the source location of the signal. Obtaining the signal of the target can be accomplished through multiple techniques such as through Cellular Broadcast Message Request or through the use of IMSI Tracking or WiFi MAC Address Tracking.

## Related CWE (1)

- [CWE-201 — Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html) — The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Skills required

- [Low] Commercial tools are available.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
