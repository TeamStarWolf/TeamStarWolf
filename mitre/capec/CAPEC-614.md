# CAPEC-614 — Rooting SIM Cards

<a id="capec-614"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

SIM cards are the de facto trust anchor of mobile devices worldwide. The cards protect the mobile identity of subscribers, associate devices with phone numbers, and increasingly store payment credentials, for example in NFC-enabled phones with mobile wallets. This attack leverages over-the-air (OTA) updates deployed via cryptographically-secured SMS messages to deliver executable code to the SIM.

## Related CWE (1)

[CWE-327](/CWE_REFERENCE.md)

**Prerequisites:** ::A SIM card that relies on the DES cipher.::

**Skills required:** ::SKILL:This is a sophisticated attack, but detailed techniques are published in open literature.:LEVEL:Medium::

**Mitigations:** ::Upgrade the SIM card to use the state-of-the-art AES or the somewhat outdated 3DES algorithm for OTA.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
