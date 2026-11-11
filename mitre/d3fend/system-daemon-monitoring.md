# D3FEND: System Daemon Monitoring

<a id="system-daemon-monitoring"></a>

D3FEND tactic: Detect  
Digital artifacts: Operating System Process  

Tracking changes to the state or configuration of critical system level processes.

## ATT&CK techniques countered (3)

- [T1053: Scheduled Task/Job](/mitre/techniques/T1053.md): monitors. Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- [T1053.005: Scheduled Task](/mitre/techniques/T1053-005.md): monitors. Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.
- [T1685: Disable or Modify Tools](/mitre/techniques/T1685.md): monitors (D3FEND maps the revoked predecessor T1562.001). Adversaries may disable, degrade, or tamper with security tools or applications (e.g., endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors, etc.) to impair or reduce visibility of defensive capabilities.

## Related pages

- [Application-based Process Isolation](/mitre/d3fend/application-based-process-isolation.md), which also counters 3 of these techniques
- [Hardware-based Process Isolation](/mitre/d3fend/hardware-based-process-isolation.md), which also counters 3 of these techniques
- [Host Reboot](/mitre/d3fend/host-reboot.md), which also counters 3 of these techniques
- [Host Shutdown](/mitre/d3fend/host-shutdown.md), which also counters 3 of these techniques
- [Kernel-based Process Isolation](/mitre/d3fend/kernel-based-process-isolation.md), which also counters 3 of these techniques
- [Process Lineage Analysis](/mitre/d3fend/process-lineage-analysis.md), which also counters 3 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
