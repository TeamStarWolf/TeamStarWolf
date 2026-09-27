# CAPEC-501 — Android Activity Hijack

<a id="capec-501"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary intercepts an implicit intent sent to launch a Android-based trusted activity and instead launches a counterfeit activity in its place. The malicious activity is then used to mimic the trusted activity's user interface and prompt the target to enter sensitive data as if they were interacting with the trusted activity.

## Related CWE (1)

[CWE-923](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have previously installed the malicious application onto the Android device that will run in place of the trusted activity.::

**Skills required:** ::SKILL:The adversary must typically overcome network and host defenses in order to place malware on the system.:LEVEL:High::

**Mitigations:** ::To mitigate this type of an attack, explicit intents should be used whenever sensitive data is being sent. An 'explicit intent' is delivered to a specific application as declared within the intent, whereas an 'implicit intent' is directed to an app


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
