# Living Off the Land (LOTL) Detection Reference

> **Living off the land means the adversary operates through software your environment already trusts** — built-in administrative binaries, scripting engines, remote-management services, and cloud control-plane APIs — instead of introducing malware that defenses could catch. The joint guidance [Identifying and Mitigating Living Off the Land Techniques](https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques) (CISA, NSA, FBI, DOE, EPA, TSA, plus the Australian, Canadian, UK, and New Zealand cyber centres, February 7, 2024) states plainly why it keeps succeeding: *"many organizations do not implement security best practice capabilities that support detection of living off the land."*

This reference is the defender's side of that story: the telemetry to enable, the baselines that make anomalies visible, the prioritized practices from the joint guidance, and the hardening that shrinks the abusable surface. It deliberately stays at the level public advisories use — behaviors and program actions, not tradecraft. For specifics on any individual binary, consult the upstream catalogs and the guidance PDF; this page treats them strictly as defensive inventories.

**Related:** [Threat Hunting](THREAT_HUNTING_REFERENCE.md) · [Detection Rules](DETECTION_RULES_REFERENCE.md) · [SIEM Detection Content](SIEM_DETECTION_CONTENT.md) · [Detection Strategies by Tactic](detections/strategies/README.md) · [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md)

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| **Deployable rule and query content** (Sigma, SPL, KQL) | [Detection Rules](DETECTION_RULES_REFERENCE.md) · [SIEM Detection Content](SIEM_DETECTION_CONTENT.md) |
| **Hunting procedure and playbooks** | [Threat Hunting](THREAT_HUNTING_REFERENCE.md) · [Threat Hunting Playbooks](THREAT_HUNTING_PLAYBOOKS.md) |
| **Per-tactic detection strategy pages** | [Detection Strategies by Tactic](detections/strategies/README.md) |
| **EDR/endpoint-agent capability and selection** | [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md) |
| **Platform hardening baselines** | [Windows Hardening](WINDOWS_HARDENING_REFERENCE.md) · [Linux Hardening](LINUX_HARDENING_REFERENCE.md) · [macOS Security](MACOS_SECURITY_REFERENCE.md) |
| **Who Volt Typhoon are and what else they did** | [Threat Group Profiles](THREAT_GROUP_PROFILES.md) · [Threat Actors](THREAT_ACTORS.md) |
| **The LOTL detection program itself** — catalogs, telemetry, patterns, application control, metrics | **This document** |

---

## The detection problem, stated honestly

LOTL is not a signature problem — it is a **baseline problem**. The same binary, run by your IT team and by an intruder, produces near-identical telemetry. The joint guidance's analysis of network-defense weaknesses explains where defenders lose:

| Weakness the guidance documents | Why it matters |
|---|---|
| Default logging configurations | They rarely capture command lines, script content, or management-instrumentation activity, so the decisive evidence is never recorded; some necessary telemetry is even sold as paid "enhanced logging" |
| Untuned EDR plus discrete IOCs | Vendors and admins often treat system utilities as safe by definition, and simple indicator matching breaks the moment an actor varies syntax or renames an artifact |
| Blanket allow policies for admin tools | An exception written for administrator convenience becomes an unmonitored corridor; the guidance calls out overly broad exceptions for remote-execution utilities as a recurring red-team finding |
| IT/security silos | Nobody can articulate what *normal* administration looks like, so nothing can be judged abnormal; investigations stretch for months |
| Broad IP allowlists for cloud/hosting ranges | Anyone can rent address space inside them, including adversaries |

CISA notes its own red teams routinely reach full domain compromise using only these gaps — with little to no investment in tooling — because the assessed organizations had no baselines against which the activity looked unusual.

The guidance is equally blunt about why indicator matching fails here: threat actors *"bypass conventional, 'known-bad' detections by modifying common IOCs such as filenames, file paths, and command and control destinations,"* and it documents state-sponsored actors varying command-line syntax rather than reusing any fixed string. A detection pinned to one exact artifact dies on the first variation; every pattern in this page's detection-engineering section exists to survive that.

---

## Authoritative sources

Every fact in this page traces to these documents and community catalogs. (Full link list in [Sources](#sources).)

| Source | What it gives a defender |
|---|---|
| [Joint Guidance: Identifying and Mitigating LOTL Techniques](https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques) (Feb 7, 2024) | The canonical cross-agency playbook: prioritized detection and hardening practices, hunting recommendations, platform appendices ([PDF](https://www.cisa.gov/sites/default/files/2025-03/Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf)) |
| [AA23-144a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a) (May 24, 2023) | The Volt Typhoon advisory that pushed LOTL to the top of the agenda: state-sponsored intrusions into US critical infrastructure conducted almost entirely through built-in tools |
| [AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) (Feb 7, 2024) | Follow-up assessment: pre-positioning for disruptive effect in Communications, Energy, Transportation, and Water sectors, with concrete log-based indicators for hunts |
| [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | Community catalog of Windows binaries/scripts/libraries with dual-use functionality, mapped to ATT&CK and Sigma |
| [GTFOBins](https://gtfobins.org/) | The Unix/Linux counterpart (now at gtfobins.org; the old github.io address redirects) |
| [LOOBins](https://www.loobins.io/) | The macOS counterpart |
| [LOLDrivers](https://www.loldrivers.io/) | Windows drivers abused to undermine security controls |
| [LOLRMM](https://lolrmm.io/) | Remote monitoring and management (RMM) products observed in incidents |
| [LOTS Project](https://lots-project.com/) | Legitimate websites and services abused for phishing, C2, exfiltration, and payload staging |

The joint guidance itself points to the LOLBAS, GTFOBins, LOOBins, and LOLDrivers catalogs as the reference inventories. **Use them defensively:** each entry is a candidate for an application-control decision, a usage baseline, and an alert on out-of-baseline use — not a list to memorize mechanics from. The next section covers each catalog as a program input.

---

## The community catalogs as defensive inventories

Six community projects between them inventory the trusted-software surface LOTL activity moves through. All figures below were checked against the live sites and machine-readable feeds in September 2026 — **they drift constantly; consume the feeds on a schedule, never a one-off copy.**

| Catalog | Platform / scope | Size (checked Sept 2026) | ATT&CK crosswalk | License | Machine-readable |
|---|---|---|---|---|---|
| [LOLBAS](https://lolbas-project.github.io/) | Windows: Microsoft-signed binaries, scripts, libraries | 245 entries in the project's JSON API | Yes — project-published ATT&CK Navigator layer; per-entry technique IDs | GPL-3.0 | YAML per entry; JSON API |
| [GTFOBins](https://gtfobins.org/) | Unix/Linux executables that can bypass local security restrictions on misconfigured systems | 478 executables across 11 functions and 4 contexts (JSON API) | Yes — ATT&CK Navigator layer; `mitre.json` in the repo | GPL-3.0 | JSON API |
| [LOOBins](https://www.loobins.io/) | macOS built-in binaries | 62 binaries, 183 use cases (site-stated) | Entries categorized into ATT&CK tactics | GPL-3.0 | JSON export; PyLOOBins SDK/CLI on PyPI |
| [LOLDrivers](https://www.loldrivers.io/) | Windows drivers: the BYOVD surface | 697 drivers (574 vulnerable, 123 malicious), ~2,400 samples (site-stated) | None observed on the site — entries carry hashes and detections instead | Apache-2.0 | YAML per driver; JSON/CSV API; Sigma, YARA, Sysmon, ClamAV content; App Control blocklist policy |
| [LOLRMM](https://lolrmm.io/) | RMM products abusable as ready-made remote access | 341 tools in the project's JSON API | None observed — entries carry artifacts (executables, domains) and Sigma references instead | Apache-2.0 | YAML per tool; JSON/CSV API; Sigma rules |
| [LOTS Project](https://lots-project.com/) | Legitimate websites usable for phishing, C2, exfiltration, download | 175 sites (counted from the page) | No | None published | None published (HTML only) |

### LOLBAS, the Windows inventory

The [LOLBAS Project](https://lolbas-project.github.io/) documents Windows "Living Off The Land Binaries, Scripts and Libraries" under explicit criteria: an entry must *"be a Microsoft-signed file, either native to the OS or downloaded from Microsoft,"* have *"extra 'unexpected' functionality,"* and have functionality useful to an adversary. The signature criterion is the defender's headline: **every LOLBAS entry passes naive "trusted publisher" checks by construction**, which is exactly why publisher-only allowlisting fails against LOTL. Each entry carries ATT&CK technique IDs and detection pointers (including Sigma), and the project publishes an ATT&CK Navigator layer plus a JSON API — the natural source for a SIEM lookup table of catalog names and expected paths.

### GTFOBins, the Unix inventory

[GTFOBins](https://gtfobins.org/) catalogs Unix executables *"that can be used to bypass local security restrictions in misconfigured systems,"* and is explicit that it is *"not a list of exploits"* — the risk it documents comes from configuration. Its structure is what makes it consumable: each of the 478 executables is tagged by **function** (shell, file read/write, upload/download, library load, privilege escalation, and so on) and **context** (unprivileged, sudo, SUID, capabilities). For a defender the context axis is a direct audit query: any binary your servers expose with SUID bits, file capabilities, or sudo delegation that also appears in GTFOBins under that context is a standing privilege-escalation risk until the configuration is justified. Feed the JSON API into your sudoers and SUID audit tooling.

### LOOBins, the macOS inventory

[LOOBins](https://www.loobins.io/) ("Living Off the Orchard") documents 62 macOS built-in binaries across 183 use cases, categorizes each into ATT&CK tactics, and ships a JSON export plus the PyLOOBins Python SDK/CLI. It is the smallest catalog, which is itself useful: baselining 62 binaries per macOS fleet role is a bounded, finishable task. Pair it with the native telemetry in [macOS Security](MACOS_SECURITY_REFERENCE.md).

### LOLDrivers, the bring-your-own-vulnerable-driver surface

[LOLDrivers](https://www.loldrivers.io/) is the odd one out: it catalogs not dual-use tools but **signed Windows drivers that undermine the security model** — 697 of them, split between vulnerable (574) and outright malicious (123), with roughly 2,400 known sample hashes. Its consumption model is also different: rather than baselining usage, you **block** — the project publishes Sigma, YARA, and Sysmon detection content plus a ready-made App Control for Business policy that denies the cataloged drivers by hash. Treat it as the community-maintained complement to Microsoft's own vulnerable driver blocklist (covered under application control below), and alert on any driver load matching the catalog on hosts where the blocklist is not yet enforced.

### LOLRMM, the remote-management surface

[LOLRMM](https://lolrmm.io/) (Apache-2.0, from the same magicsword-io community as LOLDrivers) documents 341 remote monitoring and management products, each as a YAML record with the artifacts a deployment leaves — executable names, installation paths, network domains — plus Sigma detection references and JSON/CSV APIs. It operationalizes the joint guidance's instruction to consolidate on a sanctioned remote-access product and disable and alert on the rest: diff the catalog's artifact list against your software inventory and egress logs on a schedule, and every hit that is not your sanctioned product is a finding — either shadow IT or an intrusion, and both need handling.

### LOTS, living off trusted sites

The [LOTS Project](https://lots-project.com/) (maintained by mrd0x) extends the same idea to the network: 175 legitimate, high-reputation websites and services that public reporting shows being abused for phishing, command and control, exfiltration, and payload download, tagged by those four categories. It is the weakest catalog as a machine input — no license, no feed, no ATT&CK mapping — and the one where naive consumption does the most damage: **you cannot blocklist it wholesale**, because it is substantially a list of the internet's most business-critical domains. Its correct use is as a review list for egress analytics: which of these services do we actually use, from which hosts, by which processes — so that a server or service account initiating first-ever traffic to one of them becomes an investigable event (the network-egress pattern below).

### Consuming a catalog as a program input

1. **Pull the machine-readable feed** (JSON/CSV/YAML) on a schedule; diff against the last pull so new entries open review tickets rather than silently widening a list.
2. **Generate SIEM lookup tables** from the feed — binary names and paths for LOLBAS/GTFOBins/LOOBins, driver hashes for LOLDrivers, executable names and domains for LOLRMM — and join them against process-creation, driver-load, and egress telemetry. See [SIEM Detection Content](SIEM_DETECTION_CONTENT.md) and [Detection Rules](DETECTION_RULES_REFERENCE.md).
3. **Drive allowlist decisions, not just alerts:** each entry present in your environment gets an explicit, recorded decision — who may run it, where, and whether application control restricts it. This page's program section tracks that coverage as a metric.
4. **Respect what a catalog is:** community-maintained, dual-use inventory. Membership is a review trigger, never a verdict — and absence from a catalog is not a clean bill of health.

Where each feed plugs into the telemetry this page enables:

| Catalog | Join against | Defensive action |
|---|---|---|
| LOLBAS | 4688 / Sysmon 1 process names, paths, PE original file names | Per-entry baseline plus recorded application-control decision; alert on out-of-baseline use |
| GTFOBins | sudoers, SUID, and file-capability audit output; auditd exec records | Remove or justify the *context* (sudo/SUID/capability) that makes an entry a live risk on that host |
| LOOBins | ES process events / Santa decisions on macOS | Bounded per-role baseline of the 62 binaries |
| LOLDrivers | Sysmon 6 driver-load hashes; CodeIntegrity events under an App Control policy | Block by hash via the project's App Control policy or Microsoft's blocklist; alert on catalog matches where blocking isn't enforced yet |
| LOLRMM | Software inventory; egress/DNS logs against the per-tool domain artifacts | Reconcile against the sanctioned-RMM decision; every other hit is shadow IT or an intrusion |
| LOTS | Proxy/DNS/Zeek destination metadata | Per host+process+account first-seen and volume baselines on the trusted services you actually use |

---

## Where LOTL lands in ATT&CK

There is **no official "LOTL technique list" in MITRE ATT&CK** — living off the land is a style that cuts across tactics, not a technique. The joint guidance's appendix organizes observed activity under Execution (TA0002), Credential Access (TA0006), Discovery (TA0007), Lateral Movement, and Command and Control. The techniques below are the recurring anchors, each verified against the current framework:

| Technique | ID | Why it recurs in LOTL activity |
|---|---|---|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | The center of gravity — PowerShell (.001), Windows Command Shell (.003), Unix Shell (.004), through Cloud API (.009) |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | Management plumbing present on every Windows host |
| Scheduled Task/Job | [T1053](https://attack.mitre.org/techniques/T1053/) | Persistence via Scheduled Task (.005) and Cron (.003) |
| System Services | [T1569](https://attack.mitre.org/techniques/T1569/) | Service Execution (.002) underlies common remote-execution tooling |
| System Binary Proxy Execution | [T1218](https://attack.mitre.org/techniques/T1218/) | Trusted, signed OS binaries proxy attacker content |
| System Script Proxy Execution | [T1216](https://attack.mitre.org/techniques/T1216/) | The script-based variant |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Artifacts dressed up as legitimate ones |
| Indicator Removal | [T1070](https://attack.mitre.org/techniques/T1070/) | Log and artifact cleanup to stay baseline-shaped |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | The identity half of LOTL: stolen legitimate credentials |
| Remote Services | [T1021](https://attack.mitre.org/techniques/T1021/) | Lateral movement over RDP (.001), SMB/Admin Shares (.002), SSH (.004), WinRM (.006) |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | Internal staging via native copy mechanisms |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Native download utilities fetch what the OS lacks |
| OS Credential Dumping: NTDS | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | Domain credential theft with built-in directory utilities — Volt Typhoon's documented signature |

**Framework version notes (check before re-mapping anything):**

- **ATT&CK v18** (October 28, 2025) replaced per-technique detection text with structured **Detection Strategies and Analytics** — 691 strategies and 1,739 analytics for Enterprise at launch — and deprecated the old Data Sources ([release notes](https://attack.mitre.org/resources/updates/updates-october-2025/)). ATT&CK's detection content is now platform-specific analytics tied to data components, which lines up directly with the telemetry section below.
- **ATT&CK v19** (April 2026) split Defense Evasion into **Stealth (TA0005)** and **Defense Impairment (TA0112)** ([MITRE's announcement](https://medium.com/mitre-attack/att-ck-v19-the-defense-evasion-split-ics-sub-techniques-new-ai-social-engineering-coverage-ff329cb65d66)). T1218, T1216, T1036, T1070, and T1078 now sit under Stealth, while tool-tampering behaviors moved to Defense Impairment under new technique IDs. Navigator layers and coverage maps built before v19 need their tactic assignments re-pinned.

**In this library:** [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) · [ATT&CK Data Components](ATTACK_DATA_COMPONENTS.md) · [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [D3FEND countermeasures](D3FEND_REFERENCE.md)

---

## Telemetry foundation

You cannot baseline what you never record. The guidance's first priority is comprehensive **and** verbose logging, aggregated out-of-band where an intruder cannot tamper with it. The concrete switches:

| Layer | Enable | Notes |
|---|---|---|
| Process creation with command line | Security event **4688** plus the *Include command line in process creation events* policy | Both are off by default; see [Microsoft's command-line process auditing doc](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing). Command lines can contain secrets — control who can read the security log |
| PowerShell visibility | Module logging (**4103**) and script block logging (**4104**) in the `Microsoft-Windows-PowerShell/Operational` log | See [about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows); the joint guidance also points to the NSA/CISA/NCSC *Keeping PowerShell* paper for balancing capability against risk |
| WMI activity | WMI event tracing | Called out by name in the guidance as required visibility |
| Directory service integrity | Windows **ESENT** application log events **216, 325, 326, 327** | The guidance and AA24-038A flag these as potential indicators of the domain credential database being copied — a high-value hunt lead |
| Linux | Audit framework coverage of shell activity and system calls; file-integrity monitoring on `/etc/crontab`, `/etc/cron.*/*`, and systemd unit files | Per the guidance's Linux recommendations |
| macOS | Verbose logging for terminal commands, AppleScript activity, and access to key built-in networking/automation binaries | Per the guidance's macOS recommendations; don't assume the platform is inherently safe |
| Network | Traffic metadata via Zeek; open-source NIDS such as Snort or Suricata; sensors at segment intersections, VPN gateways, and DMZs | LOTL network evidence is transient — if no sensor captured it, it never existed for you |
| Cloud | Control-plane audit logs everywhere: AWS CloudTrail, Azure Activity Log, Google Cloud Audit Logs — including regions and services you don't actively use | Idle regions are where activity goes unwatched; also log network gateways and storage access |
| Aggregation | Centralized, out-of-band SIEM with long retention | Local logs get cleared or roll over; routinely audit that events still arrive and still trigger alerts after every upgrade |

For log-management architecture, the guidance defers to [NIST SP 800-92 Rev. 1](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd) (Cybersecurity Log Management Planning Guide — still an initial public draft as of this writing); for small teams, CISA's free **Logging Made Easy** distribution is a starting point.

### Windows: the decisive event sources

The joint guidance anchors its Windows hunting advice to the process-creation streams and script-visibility layers below. Event names verified against [Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (page current as of September 2026):

| Source | Channel / mechanism | What it records |
|---|---|---|
| Security **4688** | Windows Security log + command-line inclusion policy | Native process creation with parent process and (once enabled) the command line — the evidence base the guidance's own detection walk-throughs rest on, alongside Sysmon 1 |
| PowerShell **4103** / **4104** | `Microsoft-Windows-PowerShell/Operational` | Module/pipeline detail (4103) and script-block content as executed (4104) — script visibility at execution time |
| Sysmon **1** | `Microsoft-Windows-Sysmon/Operational` | Process creation with command line for process **and parent**, file hashes, the original file name from the PE header (the guidance's recommended check for renamed utilities), and a ProcessGUID that survives PID reuse — the join key for lineage analytics |
| Sysmon **3, 22** | same | Network connections attributed to a process (3, off by default) and DNS queries per process (22) — the host half of the network-egress pattern below |
| Sysmon **6** | same | Driver loaded, with hash and signature — the event a LOLDrivers hash lookup joins against |
| Sysmon **7, 8, 10, 25** | same | Image/DLL load (7, off by default), remote-thread creation (8), process access (10), process-image tampering (25) |
| Sysmon **11, 23/26** | same | File created (watch autostart and staging paths); file deletion |
| Sysmon **12, 13, 14** | same | Registry object create/delete, value set, rename — the auto-start locations in the guidance's persistence audits |
| Sysmon **17, 18** | same | Named pipe created/connected — common remote-execution plumbing |
| Sysmon **19, 20, 21** | same | WMI event filter, consumer, and filter-to-consumer binding — WMI persistence made visible |
| AMSI | [Antimalware Scan Interface](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) | Script content handed to the registered antimalware engine at execution time, after de-obfuscation. Integrated components per Microsoft: UAC elevation, PowerShell, Windows Script Host, JavaScript/VBScript, and Office VBA macros |
| ESENT **216, 325, 326, 327** | Application log | Directory-database engine activity — the hunt lead AA24-038A ties to domain-credential theft |

Sysmon is configuration-driven: several high-value event types are off by default and all of them need include/exclude rules tuned to your environment — see Microsoft's configuration guidance (which the joint guidance itself cites) and this library's [Detection Rules](DETECTION_RULES_REFERENCE.md) for rule content that consumes these events.

### Linux: auditd first, eBPF for depth

| Source | What it gives you | Notes |
|---|---|---|
| **auditd** | Syscall-level records, including process execution, driven by administrator-defined rules | Recommended by name in the guidance: auditd is *"easily customizable, giving organizations the ability to monitor for specific commands, command syntax, or file/directory changes"* — and the guidance stresses relying on privileged logs like auditd because shell-history files can be edited by unprivileged users |
| File-integrity monitoring | Unauthorized changes to `/etc/crontab`, `/etc/cron.*/*`, systemd unit files | The persistence-surface audit, per the guidance |
| **Sysmon for Linux** | Microsoft's open-source port of Sysmon eventing to Linux | The guidance names "Auditd or Sysmon for Linux" as the two host-log options to ship to the SIEM |
| **eBPF-based runtime security** | Kernel-level process, syscall, and network observability with modern filtering | The current tooling generation: [Falco](https://falco.org/) (CNCF-graduated February 29, 2024), [Cilium Tetragon](https://github.com/cilium/tetragon), and [Aqua Tracee](https://github.com/aquasecurity/tracee) are prominent open-source examples |
| **SELinux / AppArmor** | Mandatory access control that both constrains and *logs* off-profile behavior | The guidance recommends them for "additional monitoring and enforcement of standard application behavior" |

### macOS: the sanctioned telemetry plane

| Source | What it gives you | Notes |
|---|---|---|
| **Endpoint Security framework** | Apple's supported API for process-execution, file, and related security events; the replacement for kernel-extension telemetry | ES clients are system extensions with an Apple-granted entitlement — full treatment, event families, and version history in [macOS Security](MACOS_SECURITY_REFERENCE.md) |
| **Unified log** | The structured system-wide log (macOS 10.12+) where Apple's own subsystems record what they did | Forward it; Gatekeeper, TCC, and XProtect activity narrate there — see [macOS Security](MACOS_SECURITY_REFERENCE.md) |
| **eslogger** | Command-line tap on the ES event stream (ships with macOS 13+), emitting JSON | A triage and detection-prototyping tool, not a production sensor |
| **Santa** | Open-source binary authorization: allow/deny decisions with logging | Recommended by name in the joint guidance for monitoring macOS process executions |
| **osquery** | Endpoint state as SQL: persistence items, launchd jobs, configuration | The state complement to ES's event stream |

### Cloud: the control plane is the shell

In cloud environments the "trusted binary" is the provider's own API, so the guidance's cloud recommendations are the same pattern at a different layer — all from its own text:

| Guidance recommendation | Detection consequence |
|---|---|
| Architect enclaves with subnet and security-group separation — *"this may enable additional logs within the environment"* | Segmentation is a telemetry decision in cloud too: flows between enclaves become loggable, deniable events |
| Monitor for unusual API calls, *"especially those involving changes to security groups, configuration of cloud resources, or access to sensitive data"* | Control-plane audit logs (CloudTrail, Activity Log, Cloud Audit Logs) are the 4688 of the cloud — the baseline surface for practice 2 |
| Investigate *"unusual account behavior, such as out-of-hours logins, concurrent sign-ins from geographically disparate locations, and internal network enumeration"* | The identity pattern below, applied to cloud principals and service accounts |
| Keep infrastructure-as-code backups — *"this can be used to compare changes to environment"* | IaC is a free configuration baseline: diff deployed state against it and treat drift as a lead |
| *"Consider leveraging machine learning based anomaly detection capabilities within cloud provider security services"* | The guidance's explicit endorsement of ML-backed log analysis where rule-based review can't keep up |

**In this library:** [SIEM Reference](SIEM_REFERENCE.md) · [Network Monitoring](NETWORK_MONITORING_REFERENCE.md) · [Windows Hardening](WINDOWS_HARDENING_REFERENCE.md) · [Linux Hardening](LINUX_HARDENING_REFERENCE.md) · [macOS Security](MACOS_SECURITY_REFERENCE.md)

---

## Detection engineering: patterns that survive syntax changes

Five analytic patterns recur throughout the joint guidance's hunting recommendations. Each is behavioral — pinned to *relationships and deviations from baseline*, not exact strings — which is what lets it survive the syntax variation the guidance warns about. Rule content lives in [Detection Rules](DETECTION_RULES_REFERENCE.md) and the per-tactic pages under [Detection Strategies](detections/strategies/README.md); this section is the design logic. The guidance PDF carries the concrete examples; deliberately, this page does not.

### Pattern 1: rare-process and rare-user baselining

The guidance's core instruction: *"a particular LOLBin may be used, but always with a specific command-line or user. Assess whether alerts can be created if those LOLBins are used outside of the baseline."* And its plainest illustration of role context: *"Normal, non-technical users will typically never open a command prompt and run ipconfig. A compromised user account, on the other hand, might."*

- Scope the baseline per **host role and user population**, not per enterprise — a build server's normal is a receptionist workstation's incident.
- Seed the watch set from the catalogs above, then record, per binary actually present: who runs it, from where, how often. A first-seen execution of a catalog-listed binary on a host class where it has no history is the highest-precision alert this pattern yields.
- This pattern is inseparable from the program work in practice 2 below: a *minimal* sanctioned admin toolset, extensively logged, everything else blocked or alerted.

### Pattern 2: parent-child and process-chain anomalies

The guidance devotes a full recommendation to process lineage: monitor for productivity applications spawning script interpreters — on Windows, Office applications launching command shells or script hosts (*"a red flag, as it is uncommon"*); on Linux, text editors initiating network tools; on macOS, productivity apps spawning shells or interpreters. It adds a second-order signal: common discovery commands are individually unremarkable, but *"their launch from an Office application is anomalous and warrants investigation."*

- Build these analytics on telemetry that records lineage natively: Sysmon 1's parent fields and ProcessGUID, 4688's parent process, auditd's parent PID, ES process events on macOS.
- *"Establish baselines for normal parent-child process activities to effectively spot deviations"* — enumerate the legitimate spawn relationships per application and alert outside them, rather than maintaining an ever-growing list of bad pairs.
- Know the limits: the guidance's appendix notes actors manipulate process ancestry and orphan child processes, so corroborate lineage analytics with logon-session correlation rather than trusting the tree alone.

### Pattern 3: command-line anomaly signals

The guidance directs defenders to develop *"targeted detection strategies for high obfuscation techniques"* in command-line and scripting activity, and names the pattern classes to scrutinize: heavy use of escape characters, concatenation of commands, excessive reliance on environment variables, and encoded payloads. It likewise recommends watching command-line telemetry for the syntax used to interact with NTFS alternate data streams, and — because actors shorten and vary flag syntax rather than reusing known strings — checking a binary's PE-header original file name against its on-disk name to catch renamed utilities. The PDF gives the concrete token-level examples; consume them there and encode them as SIEM analytics over 4688/Sysmon 1 command-line fields, per [Detection Rules](DETECTION_RULES_REFERENCE.md).

Two engineering notes keep this pattern honest:

- The guidance prescribes **pattern classes plus baseline deviation**, not fixed thresholds. Numeric command-line length or entropy scoring is a common SIEM implementation of the same idea — treat it as your implementation choice, tuned per environment, not as a published standard.
- Obfuscation analytics are the *complement* of Pattern 1, not a replacement: an unobfuscated command from the wrong account should still fire on baseline deviation even when every obfuscation score is quiet.

### Pattern 4: network egress and living off trusted sites

The guidance's network sections describe the same baseline logic at the wire. Its highest-signal moves:

- **Treat denied traffic in a segmented network as signal**, and investigate abnormal flows rather than tuning thresholds — its examples include directory queries reaching a domain controller from non-domain hosts, file-share access across sites or business roles, and workstations talking directly to database servers that only an application tier should reach.
- **Join network and host telemetry** so every flow carries a user and a process, and *"compare the destination with on-network artifacts as mismatched information could indicate malicious traffic"* — its examples include traffic on an authentication port from a process that has no business speaking it, and remote-access update traffic going to an unrelated but legitimate-appearing site.
- **Reconcile host-side network logs against network-device logs**; a discrepancy between the two views is itself a finding.

For LOTS-style abuse, destination reputation is useless by definition — the destination is genuinely reputable. What remains detectable is the **relationship**: which internal host, which process, which account, first-seen use of a trusted service by a server or service account, and volume/direction shifts against that pairing's own history. Use the LOTS catalog to decide which trusted services deserve those per-pairing baselines, and instrument via proxy/DNS logs and Zeek metadata — see [Network Monitoring](NETWORK_MONITORING_REFERENCE.md) and the command-and-control page under [Detection Strategies](detections/strategies/README.md).

### Pattern 5: identity paths and post-logon sequence

The guidance's authentication-log strategy has a structural premise: **constrain the legitimate paths first, so violations become cheap to detect.** Restrict domain administrator accounts so they can only log into domain controllers; route other administrative roles through privileged access workstations and bastion hosts, which it describes as *"controlled and predictable jump points to enforce standardized login procedures."* Once the sanctioned path is that narrow, an authentication that bypasses it is not an anomaly score — it is a policy violation with a page attached.

On top of the constrained paths, compare activity with each account's own history. The guidance's list of unusual behaviors: odd login hours; access conflicting with expected work schedules or planned holiday breaks; rapid-succession or high-volume access attempts followed by a successful login; unusual access paths; concurrent sign-ins from multiple geographic locations; and impossible travel. Its practice 2 adds the subtlest signal in this document: profile even the *sequence* of applications a privileged account opens after logon — a session whose order deviates from that account's own precedent deserves review when every individual event looks routine. See [Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) and the credential-access and lateral-movement pages under [Detection Strategies](detections/strategies/README.md).

---

## The five prioritized detection practices

The joint guidance orders its detection recommendations explicitly. Summarized faithfully:

1. **Log comprehensively and verbosely, aggregate centrally, out-of-band.** Coverage first (all platforms, shells, audit trails, cloud control planes), then depth (command lines, script content, management-instrumentation tracing). Centralization defeats local log tampering and extends history. Audit the pipeline itself on a schedule — updates silently break forwarding.
2. **Establish and continuously maintain baselines** of installed software, account behavior, and network traffic. Specifics the guidance insists on: select a *minimal* set of sanctioned admin tools, log them extensively, and block or alert on all others; profile privileged accounts (tools used, commands, hours, devices — even the *sequence* of applications after logon); use privileged access workstations for administration, starting with directory administrators; bound the behavior of service accounts and scanners; inventory per-host software and uninstall what the host doesn't need; give internet-facing hosts extra scrutiny; baseline the dual-use binaries from the catalogs above and alert when one is used outside its established pattern.
3. **Automate continuous log review** against those baselines, prioritizing privileged accounts and crown-jewel assets such as domain controllers. Platform-specific audits: cron/systemd timers on Linux, launchd and property lists on macOS, registry auto-start locations and unusual scheduled tasks on Windows, anomalous API calls in cloud. The guidance also endorses machine-learning anomaly detection within cloud-provider security services for log analysis beyond rule-based methods.
4. **Reduce alert noise.** Avoid overly broad match-everything rules (in inclusions *and* exclusions); work with IT to shrink the set of allowed admin tools and logon paths (a typical business user never opens a shell; a domain admin account should authenticate only to domain controllers); disable and alert on remote-access software the organization hasn't sanctioned; adopt a detection maturity model and an alert naming convention that carries the ATT&CK phase.
5. **Deploy user and entity behavior analytics (UEBA)** to correlate across data sources and surface compromised accounts and insider misuse that rule-based tools miss.

**In this library:** [Detection Rules](DETECTION_RULES_REFERENCE.md) · [Threat Hunting Playbooks](THREAT_HUNTING_PLAYBOOKS.md) · [Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)

---

## Hardening that shrinks the surface

Detection gets easier every time you remove a legitimate reason for a tool to run. The guidance's hardening priorities:

1. **Apply hardening guidance and refuse insecure defaults.** Vendor baselines, CIS Benchmarks, and NIST guidance; harden frequently targeted services and disable superfluous ones. For Microsoft cloud tenants, CISA's SCuBA secure configuration baselines; for macOS, the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security). Treat identity providers, directory services, MDM, and cloud consoles as critical assets with tightly restricted administrative paths, and prefer admin tools that do not cache credentials on remote hosts.
2. **Application control, configured per business role.** On Windows this means [App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol) (the renamed Windows Defender Application Control) and AppLocker — policy-driven control over executables, scripts, installers, DLLs, and packaged apps; on macOS, Gatekeeper enforcement with monitoring for bypass attempts. Channeling activity through a narrow, well-logged path is as much a *detection* win as a prevention one. Depth treatment below.
3. **Segment the network and watch the seams.** Least-privilege access between segments limits blast radius when credentials are stolen; inter-segment traffic analysis catches what host telemetry missed. The guidance names zero trust architecture as the long-term strategy — no binary or account is automatically trusted.
4. **Authentication controls.** Phishing-resistant MFA everywhere, privileged access management with just-in-time and time-bounded elevation, role-based access, strict cloud identity policy with key rotation, and regular review of Unix privilege-delegation configuration.

Plus the positioning moves the guidance adds:

- **Restrict outbound internet access from back-end servers** by default; where egress is required, allow only named destinations, and investigate raw connections to IP addresses that have no matching DNS query.
- **Consolidate remote-access/RMM software** to one sanctioned product plus a backup, audit devices for everything else, and alert on the unsanctioned remainder ([LOLRMM](https://lolrmm.io/) is the inventory to check against).
- **Limit exposure of your defensive configuration.** The guidance notes that some monitoring configurations are readable by default from the systems they watch; audit attempts to read them or tamper with logging.
- **Choose vendors on secure-by-design grounds** — products that demand broad privileges, vague firewall openings, or AV exclusions are enlarging your LOTL surface for you.

### Application control in depth: Windows

Facts verified against Microsoft Learn, September 2026.

**App Control for Business** (formerly WDAC) is Microsoft's per-machine application control: policy decides what runs, based on code-signing certificate attributes, signed file metadata or hash, path, the Intelligent Security Graph's reputation, or a managed installer. Its reach is the point for LOTL defense — Microsoft notes it *"extends beyond apps"* to scripts, MSI installers, batch files, and interactive PowerShell, which it forces into [Constrained Language Mode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes) under an enforced policy.

**Deployment is a staged program, not a switch.** Microsoft's deployment guide is unambiguous: *"All App Control for Business policy changes should be deployed in audit mode before proceeding to enforcement."* The recommended arc:

| Phase | What happens | Exit criterion |
|---|---|---|
| Design | Build a base policy — Microsoft suggests starting from the Smart App Control example policy shipped in Windows and adding trust for your line-of-business apps | Policy compiles and covers known-good software |
| **Audit** | Deploy in audit mode to a first deployment ring; collect the would-have-blocked events centrally (Defender for Endpoint Advanced Hunting or event-log forwarding) | Block events match expectations; noise burned down to explainable residue |
| Ring expansion | Widen ring by ring, still auditing, with defined success criteria per ring | Same, at scale |
| **Enforce** | Switch rings to enforced mode; keep collecting block events — they are now high-quality detection signal | Exceptions tracked, owned, and expiring |

Deployment channels: Intune/MDM, Configuration Manager, script, or Group Policy (single-policy format only).

**AppLocker's role.** Microsoft is explicit that customers who can use App Control *"should do so"* — AppLocker continues to receive security fixes but *"isn't getting new feature improvements,"* and unlike App Control it isn't serviced as a security feature under MSRC criteria. Its remaining niches: applying policy per user or group on shared devices, and covering older OS versions — Microsoft's stated best practice is to enforce App Control at the most restrictive level possible, then use AppLocker to fine-tune user-specific restrictions on top.

**The Microsoft vulnerable driver blocklist** is the OS-shipped answer to the LOLDrivers problem: a Microsoft-maintained block policy for non-Microsoft drivers with known exploitable vulnerabilities, malicious behavior, or security-model circumvention. Verified specifics: it is **enabled by default on all devices since the Windows 11 2022 Update**, and (except on Windows Server 2016) also enforced whenever memory integrity (HVCI), Smart App Control, or S mode is active; Microsoft updates it **quarterly**, with updates also delivered through monthly Windows servicing; organizations that want the most current list can deploy the downloadable blocklist as an App Control policy — validated **in audit mode first**, per Microsoft's own instruction. Microsoft also recommends pairing it with the Defender attack-surface-reduction rule for exploited vulnerable signed drivers, which blocks new vulnerable drivers being written to disk (the blocklist, not the ASR rule, is what stops an already-present driver loading — and already-running drivers need a reboot to be blocked). Note the honest caveat in Microsoft's own doc: the blocklist balances security against compatibility and *"isn't guaranteed to block every driver found to have vulnerabilities"* — which is exactly the gap the LOLDrivers feed covers with detection content.

**Smart App Control** (Windows 11 22H2 and later) applies the same engine for consumers and small businesses: only signed code or code the Intelligent Security Graph predicts safe. It starts in evaluation mode and, on enterprise-managed devices, switches off within 48 hours unless turned on — so it is not your enterprise mechanism; Microsoft positions its bundled example policy as the starting point for a managed App Control policy instead.

### Application control equivalents on Unix and macOS

- **fapolicyd** (Red Hat Enterprise Linux) is the closest Linux analogue, verified against [Red Hat's RHEL 9 documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/assembly_blocking-and-allowing-applications-using-fapolicyd_security-hardening): it *"controls the execution of applications based on a user-defined policy"* to *"prevent running untrusted and possibly malicious applications."* Trust is anchored in the package manager — *"the fapolicyd daemon uses the RPM database as a list of trusted binaries and scripts,"* with an RPM/DNF plugin keeping it current and `/etc/fapolicyd/fapolicyd.trust` for administrator additions. Rules can allow, deny, or audit by path, hash, MIME type, or trust — and Red Hat documents a **permissive mode for testing before enforcement**, the same audit-then-enforce arc as App Control. Know the default: fapolicyd does **no integrity checking** unless you enable it (file size, SHA-256, or IMA).
- **sudo policy as application control:** the guidance's instruction to review Unix privilege-delegation configuration regularly is the allowlisting decision in another form — sudoers rules that grant specific commands to specific roles are your recorded per-binary decisions, and GTFOBins' sudo context is the audit list to check them against.
- **Restrictive mount options:** the long-standing CIS-Benchmark-style hardening of mounting user-writable and removable filesystems with no-execute (and related) options removes whole directories from the executable surface; treat it as a compensating control where full allowlisting isn't yet feasible.
- **SELinux / AppArmor** confine what even an allowed binary may do, and log the attempts outside profile — enforcement and telemetry in one control, per the guidance.
- **macOS:** Gatekeeper enforcement per the guidance, with **Santa** as the open-source binary-authorization layer for rule-based allow/deny with logging — details in [macOS Security](MACOS_SECURITY_REFERENCE.md).

**In this library:** [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) · [Windows Hardening GPO](WINDOWS_HARDENING_GPO.md) · [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) · [SaaS Security](SAAS_SECURITY_REFERENCE.md)

---

## Hunt leads that have paid off

From the guidance's detection-and-hunting recommendations — each is a question you can put to your own logs today:

- **ESENT application log events 216, 325, 326, 327** on domain controllers: correlate with any sign of the directory database being staged or copied.
- **Denied traffic in a segmented network is signal.** Directory queries reaching a domain controller from a non-domain host, file-share access across sites or business roles, and workstation-to-database connections that should only ever come from an application tier — all worth an investigation rather than a threshold.
- **Host-side network logs** (web server logs, host-based sensor telemetry) reconciled against network-device logs: discrepancies between the two views are themselves a finding.
- **Authentication outliers:** out-of-hours logons, concurrent sessions from geographically implausible locations, and internal enumeration following either.
- **Scheduling and persistence surfaces:** newly modified scheduled tasks at odd times, unexpected cron or systemd timer entries, launchd changes, and registry auto-start modifications — with file-integrity monitoring backing each.
- **Sequence deviations:** the guidance emphasizes that *order* matters — a privileged account whose post-logon application sequence differs from its own history deserves a look even when every individual event is unremarkable.
- **Renamed utilities:** a system binary whose on-disk name disagrees with its PE-header original file name — the guidance's recommended masquerading check, cheap to run fleet-wide over Sysmon 1 data.

**In this library:** [Threat Hunting Playbooks](THREAT_HUNTING_PLAYBOOKS.md) · [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md)

---

## Case study: Volt Typhoon

The advisory pair that made LOTL a board-level topic:

- [AA23-144a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a) (May 24, 2023) documented PRC state-sponsored intrusions across US critical infrastructure conducted almost entirely through built-in administrative tools — chosen precisely to blend into normal Windows activity, sidestep EDR, and leave little in default logs.
- [AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) (Feb 7, 2024) assessed the goal as **pre-positioning for disruptive or destructive effect** — not espionage — against Communications, Energy, Transportation Systems, and Water and Wastewater Systems sectors, in the continental and non-continental United States including Guam, with access maintained in some victim environments **for at least five years**. Its headline mitigations are the same three pillars as this page: patch the internet-facing appliances the actor exploits for entry, enforce phishing-resistant MFA, and centralize application/access/security logging so behavior analytics are possible at all.

What the advisory record adds at behavior level, in its own language: the actors *"rarely use malware for post-compromise execution,"* relying instead on hands-on-keyboard activity through the command line and native tools — the advisory names built-in directory, network-configuration, shadow-copy, and management-instrumentation utilities among them, with repeated credential extraction from the directory database over long dwell. Its hunting guidance is correspondingly behavioral: command-line and process-creation logging (AA23-144a tells defenders to enable process-creation auditing with command-line inclusion — the source of Event ID 4688 entries; the walk-throughs that pair 4688 with Sysmon 1 are in the joint LOTL guidance, not the advisories themselves), the ESENT event cluster above, unusual files in temporary directories such as `C:\Windows\Temp\` and `C:\Users\Public\`, and baselines strong enough to make deviations visible. AA24-038A also explicitly directs readers to the joint LOTL guidance — released the same day as its companion — for the full detection program.

The lesson for defenders is uncomfortable but useful: every detection in these advisories came from *behavioral* evidence — command-line auditing, authentication patterns, directory-service logs — not from a malware signature, because for long stretches there was no malware to sign.

**In this library:** [Threat Group Profiles](THREAT_GROUP_PROFILES.md) · [Threat Actors](THREAT_ACTORS.md) · [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md) (LOTL-heavy ransomware operators use the same playbook)

---

## Running LOTL detection as a program

| Do | Don't |
|---|---|
| Decide, per dual-use binary, who may run it and record that as policy | Assume "signed by the OS vendor" means "safe for every user" |
| Build baselines jointly with IT — they know what normal administration is | Let security guess at admin behavior from logs alone |
| Validate with purple-team exercises that your telemetry actually captures sanctioned-tool misuse | Trust default EDR verdicts on system utilities |
| Track alert precision and tune continuously | Ship match-everything rules and drown the SOC |
| Re-test logging after every platform upgrade | Treat "we enabled it once" as a durable state |
| Consume the community catalogs via their machine-readable feeds, on a schedule, with diffs reviewed | Paste a catalog snapshot into a lookup table once and let it fossilize |
| Run every application-control change through audit mode with success criteria per deployment ring | Jump to enforcement, break the business, and lose the mandate for allowlisting |
| Give every allowlist exception an owner and an expiry date | Let "temporary" exceptions accumulate into an unmonitored corridor |
| Treat trusted-site egress anomalies as host+process+account questions | Try to blocklist the LOTS catalog wholesale |

### Program metrics

The originals from this page's first edition, plus the application-control metrics the depth sections above imply:

| Metric | What it tells you |
|---|---|
| Share of endpoints reporting command-line and script telemetry | Whether the telemetry foundation actually holds, per platform |
| **Catalog detection coverage:** share of catalog-listed binaries present in your environment with an explicit allow/restrict decision *and* at least one mapped detection | The core LOTL coverage number; track per catalog (LOLBAS, GTFOBins, LOOBins) |
| Count of sanctioned admin tools | Falling is good — every removal shrinks the abusable surface |
| **Audit-mode noise burn-down:** would-be-block events per week per deployment ring, trended | Readiness to enforce; a flat or rising curve means the policy or the baseline is wrong |
| **Allowlist exception count** (with owner and expiry per exception) | Policy erosion in one number; expired-but-still-active exceptions are findings |
| Unsanctioned RMM/remote-access products found per audit cycle (LOLRMM reconciliation) | Whether the consolidation mandate is holding |
| Alert precision on LOTL analytics | Whether the SOC can afford to keep the analytics on |
| Time from out-of-baseline execution to triage | The number the whole program exists to shrink |

Fold the whole loop into exposure management — LOTL findings are exactly the "compensating control absent, attack path open" exposures a [CTEM](CTEM_REFERENCE.md) cycle should surface and mobilize on.

**In this library:** [Purple Team](PURPLE_TEAM_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [CTEM](CTEM_REFERENCE.md) · [Network Defense](NETWORK_DEFENSE_REFERENCE.md)

---

## Quick reference: the paper trail

| Date | Instrument | One-line takeaway |
|---|---|---|
| **2023-05-24** | AA23-144a (Volt Typhoon) | State-sponsored critical-infrastructure intrusions conducted almost entirely through built-in tools |
| **Windows 11 2022 Update** | Microsoft vulnerable driver blocklist default-on | The BYOVD floor ships with the OS; quarterly updates, App Control policy for the latest list |
| **2024-02-07** | Joint LOTL guidance + AA24-038A, released as companions | The canonical detection/hardening playbook, and the assessment that made dwell ("at least five years") and intent (pre-positioning) explicit |
| **2024-02-29** | Falco graduates CNCF | eBPF-based runtime security reaches mainstream maturity for the Linux telemetry layer |
| **2025-10-28** | ATT&CK v18 | Detection Strategies and Analytics replace per-technique detection text; data sources deprecated |
| **2026-04** | ATT&CK v19 | Defense Evasion splits into Stealth and Defense Impairment; re-pin pre-v19 layers and coverage maps |

---

## Sources

- CISA et al. — Joint Guidance: Identifying and Mitigating Living Off the Land Techniques (Feb 7, 2024): <https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques> · [PDF](https://www.cisa.gov/sites/default/files/2025-03/Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf)
- CISA — AA23-144a: PRC State-Sponsored Cyber Actor Living off the Land to Evade Detection (May 24, 2023): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a>
- CISA — AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure (Feb 7, 2024): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a>
- LOLBAS Project: <https://lolbas-project.github.io/> · [GitHub](https://github.com/LOLBAS-Project/LOLBAS) (GPL-3.0)
- GTFOBins: <https://gtfobins.org/> · [GitHub](https://github.com/GTFOBins/gtfobins.github.io) (GPL-3.0)
- LOOBins: <https://www.loobins.io/> · [GitHub](https://github.com/infosecB/LOOBins) (GPL-3.0)
- LOLDrivers: <https://www.loldrivers.io/> · [GitHub](https://github.com/magicsword-io/LOLDrivers) (Apache-2.0)
- LOLRMM: <https://lolrmm.io/> · [GitHub](https://github.com/magicsword-io/LOLRMM) (Apache-2.0)
- LOTS Project: <https://lots-project.com/>
- Microsoft — Command-line process auditing: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing>
- Microsoft — about_Logging_Windows (PowerShell 4103/4104): <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows>
- Microsoft — Sysmon (Sysinternals): <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
- Microsoft — Antimalware Scan Interface (AMSI): <https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal>
- Microsoft — Application Control for Windows (App Control for Business / Smart App Control): <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol>
- Microsoft — Deploying App Control for Business policies: <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide>
- Microsoft — App Control and AppLocker overview: <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview>
- Microsoft — Microsoft recommended driver block rules (vulnerable driver blocklist): <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>
- Red Hat — Blocking and allowing applications by using fapolicyd (RHEL 9 Security Hardening): <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/assembly_blocking-and-allowing-applications-using-fapolicyd_security-hardening>
- Falco — CNCF graduation announcement (Feb 29, 2024): <https://falco.org/blog/falco-graduation/>
- Cilium Tetragon: <https://github.com/cilium/tetragon> · Aqua Tracee: <https://github.com/aquasecurity/tracee>
- Apple — Endpoint Security framework: <https://developer.apple.com/documentation/endpointsecurity>
- NIST SP 800-92 Rev. 1 (initial public draft): <https://csrc.nist.gov/pubs/sp/800/92/r1/ipd>

---

*This reference summarizes public guidance from CISA, NSA, FBI, and partner agencies, MITRE ATT&CK, and Microsoft, Red Hat, and Apple documentation, with community catalogs cited for defensive inventory use. It is an independent practitioner summary; consult the linked primary sources for authoritative detail. Framework facts verified September 2026 against ATT&CK v19; catalog counts, application-control documentation, and advisory facts verified September 2026 against the live sources. Catalog entry counts drift continuously — treat the figures here as a snapshot and the projects' machine-readable feeds as the source of record.*
