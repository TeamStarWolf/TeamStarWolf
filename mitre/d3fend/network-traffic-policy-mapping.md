# D3FEND: Network Traffic Policy Mapping

<a id="network-traffic-policy-mapping"></a>

D3FEND tactic: Model  
Digital artifacts: Access Control Configuration  

Network traffic policy mapping identifies and models the allowed pathways of data at the network, transport, and/or application levels.

## ATT&CK techniques countered (8)

- [T1134.005: SID-History Injection](/mitre/techniques/T1134-005.md): maps. Adversaries may use SID-History Injection to escalate privileges and bypass access controls.
- [T1222: File and Directory Permissions Modification](/mitre/techniques/T1222.md): maps. Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.
- [T1484: Domain or Tenant Policy Modification](/mitre/techniques/T1484.md): maps. Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments.
- [T1548.001: Setuid and Setgid](/mitre/techniques/T1548-001.md): maps. An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context.
- [T1548.005: Temporary Elevated Cloud Access](/mitre/techniques/T1548-005.md): maps. Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.
- [T1552.006: Group Policy Preferences](/mitre/techniques/T1552-006.md): maps. Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP).
- [T1556.009: Conditional Access Policies](/mitre/techniques/T1556-009.md): maps. Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts.
- [T1615: Group Policy Discovery](/mitre/techniques/T1615.md): maps. Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment.

## Related pages

- [Access Modeling](/mitre/d3fend/access-modeling.md), which also counters 8 of these techniques
- [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), which also counters 8 of these techniques
- [Restore Configuration](/mitre/d3fend/restore-configuration.md), which also counters 8 of these techniques
- [Account Locking](/mitre/d3fend/account-locking.md), which also counters 1 of these techniques
- [Agent Authentication](/mitre/d3fend/agent-authentication.md), which also counters 1 of these techniques
- [Change Default Password](/mitre/d3fend/change-default-password.md), which also counters 1 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
