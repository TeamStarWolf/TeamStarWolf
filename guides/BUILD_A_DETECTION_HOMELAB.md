# Build a Detection Home Lab

> **By the end of one weekend you will have a working detection lab: a Windows victim VM generating rich telemetry, a free SIEM collecting it, and a repeatable loop where you safely run a mapped ATT&CK technique and watch your own detection fire.** This is for blue-teamers, SOC analysts, and IT generalists who have never built a lab and want a defensible, zero-cost starting point.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 6-10 hours over a weekend | Beginner to intermediate | A host PC with 16 GB+ RAM, 4+ cores, ~200 GB free SSD, virtualization enabled in BIOS | A 2-VM lab (Windows victim + SIEM), Sysmon telemetry, one validated detection, and a workflow you can repeat |

## Before you start

Work through this checklist before you touch a hypervisor. Each item links to the doctrine it comes from or the official tool.

- [ ] Read the lab foundations so this guide's choices make sense in context — [HOMELAB_SETUP.md](/HOMELAB_SETUP.md) and the platform index in [LABS.md](/LABS.md).
- [ ] Confirm your host meets the "Minimum Hardware for Lab" bar (16 GB RAM minimum, SSD strongly preferred) from [LABS.md](/LABS.md).
- [ ] Enable hardware virtualization (Intel VT-x / AMD-V) in your host's BIOS/UEFI. Without it, 64-bit guest VMs will not boot.
- [ ] Pick a hypervisor and get the installer: [VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) (free for personal use), [VirtualBox](https://www.virtualbox.org/), or [Proxmox VE](https://www.proxmox.com/) for a dedicated box.
- [ ] Download a free Windows evaluation ISO from the [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter) (Windows 10/11 Enterprise, 90-180 day eval, no key needed).
- [ ] Choose one free SIEM and open its docs: [Splunk Free](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configure-splunk-licenses/about-splunk-free), [Elastic Security](https://www.elastic.co/docs/solutions/security), or [Security Onion 2.4](https://docs.securityonion.net/en/2.4/).
- [ ] Skim what telemetry matters and why, so you know what you are hunting for — [ATTACK_DATA_COMPONENTS.md](/ATTACK_DATA_COMPONENTS.md) and [ENDPOINT_SECURITY_REFERENCE.md](/ENDPOINT_SECURITY_REFERENCE.md).

> **Watch out:** Everything here stays on an isolated host-only / internal network. A detection lab does not need internet access on the victim, and giving it any raises real risk. Never point these tools at machines you do not own.

## Step 1 — Choose and install your hypervisor

Install one Type-2 hypervisor on your existing PC (fastest path) or Proxmox VE on spare hardware (best long-term). For a first lab, install **VMware Workstation Pro** (free for personal use) or **VirtualBox** on your daily machine. Follow the vendor installer defaults, then reboot.

Create one isolated virtual network for the lab so the two VMs can see each other but nothing else:
- VMware: **Edit → Virtual Network Editor → Add Network**, set it to **Host-only**.
- VirtualBox: **File → Tools → Network Manager → Host-only Networks → Create**.

**Checkpoint:** The hypervisor opens, and you have one host-only/internal network defined that you will attach both VMs to.

**Watch out:** If VM creation warns that virtualization is disabled or offers only 32-bit guests, VT-x/AMD-V is off in BIOS or blocked by another hypervisor (Hyper-V, WSL2, Docker Desktop) holding the virtualization stack. Resolve that before continuing.

## Step 2 — Build the Windows victim VM

Create a VM from the Windows 10/11 Enterprise evaluation ISO. Give it 4 GB RAM (8 GB if you can spare it), 2 vCPUs, and a 60 GB disk, matching the workstation spec in [HOMELAB_SETUP.md](/HOMELAB_SETUP.md). Attach its network adapter to the host-only network from Step 1. Complete Windows setup with a local account.

Once Windows is up, take a hypervisor **snapshot** named `clean-base` before installing anything else.

**Checkpoint:** A Windows victim VM boots, sits on the isolated network, and has a clean snapshot you can revert to.

**Watch out:** Snapshots are your undo button. Take one now and after each major step. Detection testing intentionally makes noise on this host — you want fast rollback, not a rebuild.

## Step 3 — Instrument the victim with Sysmon

Sysmon (System Monitor) is a free Sysinternals tool that writes high-fidelity endpoint events (process creation, network connections, image loads) to a dedicated Windows event log. Download it from the official [Sysinternals Sysmon page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), and grab a vetted community configuration such as [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (save it as `sysmonconfig.xml`).

From an **elevated** PowerShell prompt in the folder holding both files:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Verify events are flowing in **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**. Process-creation events appear as **Event ID 1**.

**Checkpoint:** The Sysmon/Operational log exists and is filling with Event ID 1 entries as you open apps.

**Watch out:** Run an installed config, not a default one. Bare `Sysmon64.exe -i` with no XML logs almost nothing useful; a curated config is what makes detections possible. Update the config later with `.\Sysmon64.exe -c sysmonconfig.xml`.

## Step 4 — Stand up the SIEM VM

Pick one SIEM and build a second VM for it. Match the resources to your choice:

| SIEM (free tier) | VM sizing to start | The free-tier catch to plan around |
|---|---|---|
| **Splunk Free** | 4 GB RAM, 2 vCPU, Windows or Linux | 500 MB/day index cap; no auth (you land in Splunk Web as admin), no alerting, no distributed search — 3 license warnings in a rolling 30 days disables search |
| **Elastic Security** | 8 GB RAM, 2-4 vCPU | Free **Basic** license covers the detection engine and prebuilt rules; heavier RAM footprint than Splunk Free |
| **Security Onion 2.4** | 12 GB RAM minimum for a quick VM eval; **Eval** node wants 4 CPU / 8 GB, **Standalone** 4 CPU / 24 GB | All-in-one (Zeek, Suricata, Elastic) — biggest resource ask; use **Import**/**Eval** for a first lab |

Install per the official docs linked in "Before you start." Put the SIEM VM on the same host-only network and give it a static IP you record.

**Checkpoint:** The SIEM's web console loads from your host browser (for example Splunk Web on port 8000, Kibana on 5601, or the Security Onion console).

**Watch out:** Splunk Free has no login and no alerting by design — it is fine for a learning lab, but do not treat "an alert fired" as your success signal there; you will validate via search instead. If you want scheduled alerting on a free stack, choose Elastic or Security Onion.

## Step 5 — Ship victim logs into the SIEM

Get the victim's Windows Event Logs and the Sysmon/Operational channel into the SIEM.

- **Splunk:** install the **Splunk Universal Forwarder** on the victim, point it at the Splunk indexer's IP on port **9997**, and add the **Splunk Add-on for Microsoft Windows** so Sysmon and Windows logs are parsed. Configure inputs for the Sysmon channel (`WinEventLog:Microsoft-Windows-Sysmon/Operational`).
- **Elastic:** enroll the victim with **Elastic Agent** via **Fleet** (Kibana → **Fleet → Agents → Add agent**), then add the **Windows** and **Sysmon** integrations to its policy.
- **Security Onion:** deploy the **Elastic Agent** it manages to the victim from the console's grid/agents page.

**Checkpoint:** Searching the SIEM for recent Sysmon process-creation events (for example Splunk `index=* EventCode=1`, or the equivalent in Kibana Discover) returns events from the victim in near real time.

**Watch out:** Time skew and firewalls are the usual culprits when nothing arrives. Confirm the victim and SIEM clocks agree, and that the victim's host firewall allows the forwarder/agent outbound to the SIEM IP and port.

## Step 6 — Install Atomic Red Team on the victim

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a library of small, ATT&CK-mapped tests for **safe detection validation** — you run a known technique on purpose so you can confirm your telemetry and detections catch it. Install the execution framework and the atomics from an **elevated** PowerShell prompt on the victim:

```powershell
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

By default the atomics land in `C:\AtomicRedTeam`. Import the module and confirm it loaded:

```powershell
Import-Module invoke-atomicredteam
```

**Checkpoint:** `Invoke-AtomicTest` is available, and `C:\AtomicRedTeam\atomics` contains per-technique folders (one folder per ATT&CK technique ID).

**Watch out:** Run this only on the isolated victim VM you snapshotted. Per Red Canary's own guidance, atomic tests can leave a system in an undesirable state — understand each test before running it, and never run these on a machine you rely on.

## Step 7 — Run your first safe technique test

Use the standard, non-destructive workflow: inspect, check prerequisites, run, then clean up. A good first technique is **T1059.001 (PowerShell)** — it maps cleanly to Sysmon Event ID 1 and to PowerShell logging. First inspect what the technique's tests do, without executing anything:

```powershell
Invoke-AtomicTest T1059.001 -ShowDetails
```

Then check and, if needed, install prerequisites for the specific test you chose, run it, and clean up afterward:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

**Checkpoint:** The test reports it executed, and within a minute or two the corresponding process-creation event for that test is searchable in your SIEM.

**Watch out:** If `-CheckPrereqs` prints `Elevation required but not provided`, you are not in an elevated prompt — reopen PowerShell as Administrator. Always finish with `-Cleanup`, then revert to your snapshot if a test changed system state you do not want to keep.

## Step 8 — Write and validate your first detection

You have telemetry and a known-good attack signal. Now turn that into a detection and prove it fires. Study the pattern in [DETECTION_RULES_REFERENCE.md](/DETECTION_RULES_REFERENCE.md) and the platform content in [SIEM_DETECTION_CONTENT.md](/SIEM_DETECTION_CONTENT.md), then author a rule in a portable format. Sigma is the vendor-neutral choice; install the official CLI and a backend:

```bash
pipx install sigma-cli        # or: pip install sigma-cli
sigma plugin install splunk
```

Convert a Sigma rule into your SIEM's query language (Sysmon-aware pipeline shown):

```bash
sigma convert -t splunk -p sysmon path/to/your_rule.yml
```

Paste the converted query into your SIEM. In Splunk Free, save it as a search you re-run; in Elastic or Security Onion, promote it to a scheduled detection rule so it alerts automatically. Re-run the Step 7 atomic and confirm the detection matches. Follow the closed loop from [HOMELAB_SETUP.md](/HOMELAB_SETUP.md): **attack → collect → identify → write → test → tune**.

**Checkpoint:** Running the atomic again produces a hit from your rule (a saved-search result in Splunk Free, or an alert in Elastic/Security Onion).

**Watch out:** A rule that never fires and a rule that fires on everything are equally useless. Tune with real exclusions (as in the LSASS example that filters known-good `SourceImage` values), and re-test after every change.

## What good looks like

- Reverting the victim to its `clean-base` snapshot and re-instrumenting takes minutes, not hours.
- Every atomic you run appears in the SIEM within a couple of minutes, and you can name the exact event ID and field that carried the signal.
- At least one detection fires on its intended technique and stays quiet during normal use of the victim.
- You can repeat the full **attack → collect → identify → write → test → tune** loop on a new technique without re-reading this guide.
- Nothing in the lab can reach — or be reached from — your real network or the internet from the victim.

## Go deeper

Library references:
- [HOMELAB_SETUP.md](/HOMELAB_SETUP.md) — the full lab build, network segmentation, and the detection-engineering workflow this guide condenses.
- [LABS.md](/LABS.md) — the "Minimum Viable SOC Lab" and every free practice platform, mapped by discipline.
- [SIEM_DETECTION_CONTENT.md](/SIEM_DETECTION_CONTENT.md) — platform-specific detection content and query patterns.
- [DETECTION_RULES_REFERENCE.md](/DETECTION_RULES_REFERENCE.md) — how detection rules are structured across Sigma and vendor formats.
- [THREAT_HUNTING_PLAYBOOKS.md](/THREAT_HUNTING_PLAYBOOKS.md) — turn telemetry into proactive hunts once detections are stable.
- [ATTACK_DATA_COMPONENTS.md](/ATTACK_DATA_COMPONENTS.md) — which data sources you need to detect which techniques.

Authoritative external resources:
- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — official download, event schema, and command reference.
- [Atomic Red Team documentation](https://www.atomicredteam.io/) — official install and safe-execution guidance from Red Canary.
- [Sigma CLI — SigmaHQ](https://github.com/SigmaHQ/sigma-cli) — official conversion tool, backends, and pipelines.
- [Security Onion 2.4 documentation](https://docs.securityonion.net/en/2.4/) — hardware sizing and install modes for the all-in-one NSM/SIEM.

---

*Guides are procedures, not guarantees. Tools, flags, and free-tier limits change — verify every command against the current official documentation before relying on it outside a lab.*
