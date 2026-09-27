# CAPEC-579 — Replace Winlogon Helper DLL

<a id="capec-579"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

Winlogon is a part of Windows that performs logon actions. In Windows systems prior to Windows Vista, a registry key can be modified that causes Winlogon to load a DLL on startup. Adversaries may take advantage of this feature to load adversarial code at startup.

## Mapped ATT&CK techniques (1)

- [T1547.004](/mitre/techniques/T1547-004.md)

## Related CWE (1)

[CWE-15](/CWE_REFERENCE.md)

**Mitigations:** ::Changes to registry entries in HKLMSoftwareMicrosoftWindows NTWinlogonNotify that do not correlate with known software, patch cycles, etc are suspicious. New DLLs written to System32 which do not correlate with known good software or patching may b


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
