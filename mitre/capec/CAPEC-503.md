# CAPEC-503 — WebView Exposure

<a id="capec-503"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

An adversary, through a malicious web page, accesses application specific functionality by leveraging interfaces registered through WebView's addJavascriptInterface API. Once an interface is registered to WebView through addJavascriptInterface, it becomes global and all pages loaded in the WebView can call this interface.

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires the adversary to convince the user to load the malicious web page inside the target application. Once loaded, the malicious web page will have the same permissions as

**Mitigations:** ::To mitigate this type of an attack, an application should limit permissions to only those required and should verify the origin of all web content it loads.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
