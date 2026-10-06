# Acquire and Triage a Compromised Endpoint

> By the end of this guide you will have taken a suspect Windows or Linux host from "we think it's compromised" to forensically sound memory and disk images with verified hashes, a documented chain of custody, a super-timeline, a triaged set of execution and persistence artifacts, and a written findings report with IOCs and ATT&CK mappings. Written for DFIR analysts, SOC responders, and sysadmins pulled into an investigation. No prior courtroom-forensics experience assumed, but every step is done as if the evidence might end up in one.

| Time | Difficulty | You need | You'll produce |
|---|---|---|---|
| 4-8 hours per host for acquisition + first-pass triage; a full timeline and report can run 1-3 days | Advanced: irreversible collection decisions, evidence-integrity discipline | Written authorization, a separate forensic workstation with the toolkit tested, a hardware write blocker, sterile evidence storage sized above the source, and a chain-of-custody form | Verified memory + disk images, a chain-of-custody record, a triage collection, a Plaso super-timeline, and a findings report |

This guide is the procedure behind the library's [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md); it operationalizes that reference's order-of-volatility, artifact-location, and evidence-handling sections and assumes their vocabulary (chain of custody, write blocker, hash verification, super-timeline). Forensics and incident response overlap in DFIR but optimize for different things: IR races to contain, forensics preserves evidence and defensibility. When both are true at once, this collection order lets you do the second without blocking the first. The broader response lifecycle this feeds sits in the [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) and the [IR Playbooks](/IR_PLAYBOOKS.md).

## Before you start

- [ ] Written authorization and defined scope. Who authorized the investigation, which hosts and accounts are in scope, and what the objective is. If this is potentially criminal or falls under a regulatory/breach regime, engage legal counsel and (where appropriate) law enforcement *before* acquisition, and route the work under privilege; the counsel-first pattern from [Respond to a Ransomware Incident](/guides/RESPOND_TO_RANSOMWARE.md) applies here too.
- [ ] A separate forensic workstation, not the evidence host, with your toolkit installed and *tested* offline: [Volatility 3](https://github.com/volatilityfoundation/volatility3), [Plaso](https://github.com/log2timeline/plaso), [Eric Zimmerman's Tools](https://ericzimmerman.github.io/), [KAPE](https://www.kroll.com/kape), and [Autopsy](https://www.autopsy.com/). Tools verified on the day of the incident are not verified.
- [ ] A hardware write blocker (Tableau, WiebeTech/CRU, or equivalent) for any physical disk you image, and sterile evidence storage: wiped and freshly formatted, with more free capacity than the source drive holds.
- [ ] Chain-of-custody paperwork and a case number. A custody form, an evidence log, tamper-evident bags/labels for physical media, and a single incident/case ID that every artifact, image, and note references.
- [ ] A decision on posture. Rapid triage (live collection, host stays running, speed first) versus full forensic acquisition (power-down, physical imaging, defensibility first). Most enterprise DFIR is triage-first; know which you are doing before Step 3, because it changes what you collect and in what order.
- [ ] Read the [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md) order-of-volatility, Windows artifact-location, and evidence-acquisition sections. This guide sequences them; it does not re-teach them.

## Step 1: Establish scope, authorization, and the chain of custody

Forensics is separated from ordinary log-rummaging by one thing: everything is documented and defensible from the first minute. Do this before you touch the host.

1. Record the authority and scope in your case notes: who authorized it, the date/time, the in-scope systems and accounts, and the stated objective (attribution, root cause, blast radius, litigation support).
2. Open the evidence log. Every item gets a line: what it is, where it came from (host, drive serial, source path), who collected it, the date/time (with time zone; record whether you are logging in UTC or local), and its hash once acquired.
3. Start the chain-of-custody form for each physical item. Every transfer of possession (you to storage, storage to analyst) gets a signed, timestamped handoff entry. An unbroken custody record is what makes the evidence admissible; a gap is what gets it thrown out.
4. Photograph the scene for physical acquisitions: the running screen, cable layout, drive serials, and asset tags before you disturb anything.

Checkpoint: You have a case ID, a written scope-and-authorization note, an open evidence log, and a custody form ready, before any collection command has run.

Watch out: Do not log into the suspect host with a domain admin account "just to check." Interactive logons create artifacts, overwrite volatile state, and can hand credentials to an attacker still resident in memory. Touch the host only through your collection procedure, and note every action you take on it.

## Step 2: Plan the collection order by volatility

Collect the most perishable evidence first. The canonical order comes from [RFC 3227](https://www.rfc-editor.org/rfc/rfc3227) and the [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md):

1. CPU registers and cache (rarely collectible in practice)
2. RAM: running processes, injected code, network state, encryption keys, unencrypted malware
3. Active network connections and routing/ARP state
4. Running processes and their open files
5. Disk: file system, `$MFT`, prefetch, registry, logs
6. Remote logs / SIEM (grab before rotation)
7. Physical/offline backups

The practical consequence: capture memory before you image the disk, and image the disk before you power the machine off. Powering down or rebooting destroys everything in tiers 1-4, including keys and in-memory-only malware that never touch disk. For virtual machines, prefer a hypervisor snapshot or the `.vmem`/saved-state file, which gives you memory and disk atomically without loading a driver on the guest.

Checkpoint: You have a written, ordered collection plan for this host that names the tool you will use at each tier and where each output lands.

Watch out: "Just isolate it and we'll image it tomorrow" quietly discards the entire volatile tier. If containment can't wait, use an EDR network-isolation action (which keeps the host powered and the memory intact) rather than pulling power (see the isolation step in [Respond to a Ransomware Incident](/guides/RESPOND_TO_RANSOMWARE.md)).

## Step 3: Capture volatile memory

Memory acquisition loads a kernel driver and writes a large file, so it changes the system slightly. That is expected and defensible; document that you did it, when, and with what tool.

On Windows, [WinPMEM](https://github.com/Velocidex/WinPmem) (the Velocidex-maintained, community-supported successor to the Rekall pmem tools) writes a raw image to your evidence volume:

```
winpmem.exe -o E:\evidence\HOST01\HOST01-mem.raw
```

Alternatives with similar output: Magnet RAM Capture, Belkasoft Live RAM Capturer, or Comae/DumpIt. Whichever you use, write to external evidence storage, never the suspect's own disk; writing locally overwrites the unallocated space and slack you may need later.

On Linux, [AVML](https://github.com/microsoft/avml) (Microsoft's static, distribution-agnostic acquirer) needs no on-target compilation:

```
sudo ./avml /mnt/evidence/host01-mem.lime
```

AVML writes LiME format and requires no kernel headers; note that if kernel lockdown is enabled it may be unable to read the memory source.

Immediately hash the image so your notes reference an exact artifact, and record it in the evidence log:

```powershell
Get-FileHash -Algorithm SHA256 E:\evidence\HOST01\HOST01-mem.raw
```

```bash
sha256sum /mnt/evidence/host01-mem.lime
```

Checkpoint: A memory image exists on evidence storage, its SHA-256 is in the evidence log, and the acquisition tool + version + timestamp are in your case notes.

Watch out: Acquire memory *before* running any live-triage collector that spawns processes; the collector's own activity churns the memory you are trying to preserve. Memory first, then Step 4.

## Step 4: Collect live triage artifacts

While the host is still running, pull the high-value disk artifacts as a triage package. This is often enough to answer the investigation without a full disk image.

On Windows, [KAPE](https://www.kroll.com/kape) collects a targeted artifact set (MFT, registry hives, event logs, prefetch, browser data, and more) in minutes. Collect, then parse:

```
:: Collect the SANS triage target set into a container
kape.exe --tsource C: --tdest D:\evidence\HOST01\triage --target !SANS_Triage --vhdx HOST01

:: Parse the collection with the Eric Zimmerman tool chain
kape.exe --msource D:\evidence\HOST01\triage --mdest D:\evidence\HOST01\parsed --module !EZParser
```

`--tsource/--target/--tdest` are the required switches for collection; `--module/--mdest` for parsing. `!SANS_Triage` is a compound target that pulls the standard DFIR artifact set; `!EZParser` runs the EZ Tools parsers over it. For remote or fleet-scale collection, [Velociraptor](https://github.com/Velocidex/velociraptor) does the same across many hosts and can build a standalone offline collector.

On Linux / macOS / Unix, [UAC](https://github.com/tclahr/uac) (Unix-like Artifacts Collector) respects the order of volatility and outputs a hashed archive:

```
sudo ./uac -p ir_triage /mnt/evidence
```

Use the `full` profile for a heavier collection, and add `-a ./artifacts/memory_dump/avml.yaml` to have UAC drive the memory capture too.

Checkpoint: A triage collection exists on evidence storage with its own hash/manifest, and (for KAPE) a parsed CSV set is ready for review.

Watch out: Triage collectors run *on* the live host and leave their own footprint. Note the tool, version, and exact command in your case log so a reviewer can separate your activity from the attacker's.

## Step 5: Image the disk write-blocked and verify the hash

When the case needs the full disk (deleted-file recovery, unallocated space, defensible completeness), take a forensic image. For a powered-off host or a removed drive, use a hardware write blocker so the acquisition cannot alter the source.

Windows workstation ([FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager), free, currently 4.7.x): File -> Create Disk Image -> Physical Drive, choose E01 (EnCase Evidence Format; it embeds metadata and hashes), fill in the case/examiner fields, and let it run the built-in verify pass, which re-reads the image and confirms the hash matches the source.

On Linux, image with a hash-while-imaging tool so acquisition and verification are one pass:

```bash
# Enforce a software read-only guard on the source as a backstop to the hardware blocker
sudo blockdev --setro /dev/sdb && blockdev --getro /dev/sdb   # must return 1

# dc3dd hashes as it images and writes a log
sudo dc3dd if=/dev/sdb of=/mnt/evidence/host01.img hash=sha256 log=/mnt/evidence/host01.log

# or acquire straight to E01 with libewf
sudo ewfacquire /dev/sdb
```

[Guymager](https://guymager.sourceforge.io/) gives the same result with a GUI and inline verification. Plain `dd` works but is raw-only and does not hash; if you use it, `sha256sum` the source and the image separately and confirm they match.

Record both hashes (source and image) in the evidence log; they must be identical. A hardware write blocker is the court-preferred method; software read-only flags are a backstop, not a substitute.

Checkpoint: A verified disk image (E01 or raw + separate hash) exists, the source and image SHA-256 values match and are logged, and the write-blocking method is documented.

Watch out: Never image a drive to a volume smaller than the source, and never image onto the evidence drive's own remaining space. Confirm free capacity and that the destination was wiped before this run.

## Step 6: Build the super-timeline

A super-timeline merges every timestamped artifact (file system, registry, event logs, browser history, prefetch) into one chronological view so you can see the intrusion unfold. [Plaso](https://github.com/log2timeline/plaso) (log2timeline) is the standard engine; its releases are date-versioned, so pull a current one rather than pinning a number.

```bash
# Extract events from the image (or from a mounted triage collection) into a Plaso store
log2timeline.py --storage-file host01.plaso /mnt/evidence/host01.E01

# Render a filtered CSV around the incident window
psort.py -o l2tcsv -w host01_timeline.csv host01.plaso \
  "date > '2026-09-01 00:00:00' AND date < '2026-09-29 23:59:59'"
```

Open `host01_timeline.csv` in [Timeline Explorer](https://ericzimmerman.github.io/) (Eric Zimmerman's fast CSV viewer, built for exactly this: filter, tag, and pivot across millions of rows). For collaborative or large-scale work, load the `.plaso` store into [Timesketch](https://github.com/google/timesketch) instead.

Checkpoint: A `.plaso` store and a filtered timeline CSV exist, and you can open the timeline and pivot to a specific date/time.

Watch out: A full super-timeline is enormous and mostly noise. Always filter to the incident window and pivot around known-bad timestamps (an alert time, a suspicious logon, a dropped file's creation time). Also confirm the timeline's time zone matches your evidence-log convention before you correlate anything.

## Step 7: Rapid-triage the key artifacts

With the parsed KAPE/UAC output (Step 4) and the timeline (Step 6), work the questions in order: *what ran, who logged in, how did they persist, where did they browse.* Artifact locations and forensic meaning are tabulated in the [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md).

Execution (what ran):

```
:: Prefetch — last-run times and run counts (evidence of execution)
PECmd.exe -d "D:\evidence\HOST01\triage\C\Windows\Prefetch" --csv D:\out --csvf prefetch.csv

:: ShimCache / AppCompatCache — execution/presence, from the SYSTEM hive
AppCompatCacheParser.exe -f "D:\...\config\SYSTEM" --csv D:\out

:: Amcache — SHA-1 hashes of executed binaries
AmcacheParser.exe -f "D:\...\AppCompat\Programs\Amcache.hve" -i --csv D:\out
```

Logons and event logs (who and how):

```
:: Parse EVTX to a single normalized CSV
EvtxECmd.exe -d "D:\...\winevt\Logs" --csv D:\out --csvf events.csv
```

Then hunt the logs with Sigma-backed tooling ([Hayabusa](https://github.com/Yamato-Security/hayabusa) or [Chainsaw](https://github.com/WithSecureLabs/chainsaw)):

```
hayabusa.exe csv-timeline -d "D:\...\winevt\Logs" -o hayabusa.csv
```

Focus on the DFIR-critical event IDs: 4624/4625 (logon success/failure), 4648 (explicit-credential logon), 4672 (special privileges assigned), 4688 (process creation, with command line if enabled), 4698/4702 (scheduled task created/modified), 7045 (new service), 4720 (account created), 4104 (PowerShell script block), and 1102 (Security log cleared, an eradication/anti-forensics signal).

Persistence (how they stayed): registry Run/RunOnce keys, scheduled tasks, services (7045), WMI event subscriptions, startup folders. Parse hives with [RegistryExplorer/RECmd](https://ericzimmerman.github.io/); correlate against execution artifacts above. On Linux, check cron, systemd units, `~/.bashrc`/profile scripts, and `authorized_keys`.

Browser (where they went): [Hindsight](https://github.com/obsidianforensics/hindsight) parses Chrome/Chromium history, downloads, and cache for drive-by or download vectors.

Checkpoint: You can name, with an artifact and timestamp behind each, what executed, which accounts logged in and how, the persistence mechanism(s), and any relevant browser activity, all cross-referenced against the timeline.

Watch out: Presence in ShimCache or Amcache is evidence of *existence/registration*, not always of execution; corroborate with prefetch, 4688, or the timeline before you assert a binary ran. Single-artifact conclusions are how DFIR reports get walked back.

## Step 8: Analyze the memory image

The memory captured in Step 3 is where you find what never hit disk: injected code, in-memory-only payloads, decrypted config, and live network state. [Volatility 3](https://github.com/volatilityfoundation/volatility3) (invoked as `python3 vol.py` or the `vol` entry point) is the standard framework:

```bash
python3 vol.py -f HOST01-mem.raw windows.info        # identify the image/build first
python3 vol.py -f HOST01-mem.raw windows.pslist      # processes from the active list
python3 vol.py -f HOST01-mem.raw windows.pstree      # parent/child lineage
python3 vol.py -f HOST01-mem.raw windows.psscan      # carve for hidden/terminated procs
python3 vol.py -f HOST01-mem.raw windows.cmdline     # full command lines
python3 vol.py -f HOST01-mem.raw windows.netscan     # network connections and sockets
python3 vol.py -f HOST01-mem.raw windows.malfind     # injected/unmapped executable regions
python3 vol.py -f HOST01-mem.raw windows.svcscan     # services
```

Plugin names occasionally move between releases (recent builds group some detections under `windows.malware.*`, e.g. `windows.malware.malfind`); run `python3 vol.py --help` to confirm the exact names for your version. As an alternative, [MemProcFS](https://github.com/ufrisk/MemProcFS) mounts the memory image as a browsable file system so you can navigate processes, handles, and registry as folders. For Linux memory, use Volatility 3's `linux.*` plugins (`linux.pslist`, `linux.pstree`, `linux.bash`).

Look for the classic tells: a process whose parent lineage is wrong (e.g., an Office app spawning a shell), `malfind` hits with executable private memory, network connections to unfamiliar infrastructure, and command lines with encoded or obfuscated arguments. Living-off-the-land patterns get their own hunt logic in the [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md); deeper reversing of anything you carve out belongs to the [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md).

Checkpoint: You have a documented list of suspicious processes (PID, parent, path, command line), any injected regions, and the memory-resident network connections, each tied back to a Volatility plugin and, where possible, corroborated on disk.

Watch out: Match the analysis platform to the image. Volatility 3 pulls symbol data automatically for many Windows builds, but an unusual or very new kernel may need a symbol table added; a blank result often means a symbol mismatch, not a clean host.

## Step 9: Write the findings report

The investigation is worthless if it can't be read, understood, and acted on. Write the report while the evidence is fresh, structured so a non-forensic reader gets the answer and a technical reviewer can retrace every step.

Include, at minimum:

1. Executive summary: what happened, in plain language, and the bottom line (confirmed compromise? scope? data at risk?).
2. Scope and authorization: who authorized it, what was in scope, and the objective from Step 1.
3. Evidence inventory: every image and collection with its SHA-256, acquisition tool/version, and custody reference.
4. Timeline of events: the reconstructed intrusion narrative from Step 6, in the reader's time zone, with the earliest known foothold called out.
5. Findings: what ran, initial access, persistence, lateral movement, and exfiltration, each with the supporting artifact.
6. IOCs: file hashes, paths, domains/IPs, account names, and (defanged) URLs, in a list downstream teams can consume for blocking and hunting.
7. ATT&CK mapping: observed techniques mapped to [MITRE ATT&CK](https://attack.mitre.org/) IDs, so detection engineers can close the gaps.
8. Root cause and recommendations: how they got in and the specific, owned actions that prevent a repeat.
9. Chain-of-custody appendix: the custody forms and evidence log.

Hand IOCs and ATT&CK techniques to the detection and hunting teams ([Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md)), and feed root-cause findings back into the [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) lessons-learned loop.

Checkpoint: A written report that states the verdict up front, lists every piece of evidence with its hash, and whose IOCs and ATT&CK mappings have been handed to the teams that act on them.

Watch out: State confidence honestly, for example "assessed with high confidence," "possible but unconfirmed," "no evidence of X (which is not the same as X did not happen)." A report that overstates certainty is worse than one that scopes its gaps, especially if it reaches counsel or a regulator.

## What good looks like

- Memory was captured before disk, and disk before power-down: nothing in the volatile tier was thrown away for convenience.
- Every image and collection has a SHA-256 recorded at acquisition and, for disk images, a verification pass proving source and image match.
- The chain of custody is unbroken and signed; a reviewer can account for every artifact from collection to analysis.
- Conclusions rest on corroborated artifacts (execution confirmed by two sources, not one), and the timeline is filtered, time-zone-consistent, and pivots around known-bad timestamps.
- The report leads with the answer, carries a consumable IOC list and ATT&CK mapping, and its findings became detections and hardening, not a PDF on a shelf.
- Analyst actions on the live host are logged and separable from attacker activity.

## Go deeper

In this library:

- [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md): the doctrinal base: order of volatility, Windows/Linux artifact locations, evidence handling, and the full tool catalog this guide sequences.
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md): the response lifecycle this acquisition feeds, including roles and lessons-learned.
- [IR Playbooks](/IR_PLAYBOOKS.md): scenario playbooks that call for endpoint acquisition as a step.
- [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md): for reversing anything you carve out of memory or disk.
- [Network Forensics Reference](/NETWORK_FORENSICS_REFERENCE.md): the PCAP/flow side of the same investigation.
- [Cloud, SaaS & Mobile Forensics Reference](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md): acquisition when the "endpoint" is a cloud workload or a phone.
- [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md): reading the living-off-the-land patterns you'll meet in Steps 7-8.
- [Respond to a Ransomware Incident](/guides/RESPOND_TO_RANSOMWARE.md), [Investigate a Phishing Report](/guides/INVESTIGATE_A_PHISHING_EMAIL.md): sibling guides that hand off to this procedure when a case needs evidentiary rigor.

External:

- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final): the foundational U.S. government forensics methodology.
- [NIST SP 800-61r3: Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final): the April 2025 rewrite mapped to CSF 2.0.
- [RFC 3227: Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227): the order-of-volatility source.
- [Volatility 3 documentation](https://volatility3.readthedocs.io/): memory plugin reference and usage.
- [Plaso documentation](https://plaso.readthedocs.io/): log2timeline/psort options and supported parsers.
- [SANS DFIR posters and cheat sheets](https://www.sans.org/posters/): Windows/Linux artifact and command quick reference.

*Guides are procedures, not gospel; verify every command, tool version, and flag against current official documentation before relying on it in production, and never acquire or analyze systems you are not authorized to touch.*

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
