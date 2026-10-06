# CAPEC-564: Run Software at Logon

<a id="capec-564"></a>

Abstraction: Detailed  
Status: Draft  

Operating system allows logon scripts to be run whenever a specific user or users logon to a system. If adversaries can access these scripts, they may insert additional code into the logon script. This code can allow them to maintain persistence or move laterally within an enclave because it is executed every time the affected user or users logon to a computer. Modifying logon scripts can effectively bypass workstation and enclave firewalls. Depending on the access configuration of the logon scripts, either local credentials or a remote administrative account may be necessary.

## Mapped ATT&CK techniques (4)

- [T1037: Boot or Logon Initialization Scripts](/mitre/techniques/T1037.md): Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.
- [T1543.001: Launch Agent](/mitre/techniques/T1543-001.md): Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence.
- [T1543.004: Launch Daemon](/mitre/techniques/T1543-004.md): Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence.
- [T1547: Boot or Logon Autostart Execution](/mitre/techniques/T1547.md): Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Restrict write access to logon scripts to necessary administrators.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
