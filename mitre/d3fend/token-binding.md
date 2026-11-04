# D3FEND: Token Binding

<a id="token-binding"></a>

D3FEND tactic: Harden  
Digital artifacts: Access Token  

Token binding is a security mechanism used to enhance the protection of tokens, such as cookies or OAuth tokens, by binding them to a specific connection.

## ATT&CK techniques countered (7)

- [T1134.001: Token Impersonation/Theft](/mitre/techniques/T1134-001.md): strengthens. Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls.
- [T1134.002: Create Process with Token](/mitre/techniques/T1134-002.md): strengthens. Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003: Make and Impersonate Token](/mitre/techniques/T1134-003.md): strengthens. Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1528: Steal Application Access Token](/mitre/techniques/T1528.md): strengthens. Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): strengthens. Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1558: Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md): strengthens. Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003).
- [T1558.001: Golden Ticket](/mitre/techniques/T1558-001.md): strengthens. Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.

## Related pages

- [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md), which also counters 7 of these techniques
- [Credential Compromise Scope Analysis](/mitre/d3fend/credential-compromise-scope-analysis.md), which also counters 7 of these techniques
- [Credential Hardening](/mitre/d3fend/credential-hardening.md), which also counters 7 of these techniques
- [Credential Revocation](/mitre/d3fend/credential-revocation.md), which also counters 7 of these techniques
- [Credential Rotation](/mitre/d3fend/credential-rotation.md), which also counters 7 of these techniques
- [Credential Transmission Scoping](/mitre/d3fend/credential-transmission-scoping.md), which also counters 7 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
