# macOS Security Reference

> **macOS ships with a layered, hardware-rooted security architecture — the defender's job is to manage it, observe it, and know where it stops.** [Apple's Platform Security Guide](https://support.apple.com/guide/security/welcome/web) documents a stack that runs from the Secure Enclave and a signed system volume up through Gatekeeper, XProtect, and TCC. This reference covers that architecture, the hardening baselines that configure it (NIST mSCP / SP 800-219, CIS, DISA STIG), the native telemetry planes (Endpoint Security framework, unified log), and how the platform maps into MITRE ATT&CK v19 — for defenders running Mac fleets, not for admiring the marketing diagram.

Two things changed the macOS defense picture in 2025–2026: **macOS 27 "Golden Gate" (released 2026-09-14) is the first Apple-silicon-only release**, so current-OS fleets can finally assume the Secure Enclave and the Apple silicon boot chain everywhere (macOS 26 Tahoe remains the last Intel-capable release in support); and **infostealers are now the leading macOS crimeware concern in vendor reporting** (Microsoft, Jamf Threat Labs) — attacks that mostly succeed by talking users past the platform controls rather than through them.

**Related:** [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md) · [Windows Hardening](WINDOWS_HARDENING_REFERENCE.md) · [Linux Hardening](LINUX_HARDENING.md) · [Mobile Security](MOBILE_SECURITY_REFERENCE.md) · [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md)

---

## How macOS defense fits together

Apple's own model for malware defense is three layers; the platform architecture beneath it adds two more that defenders should treat as part of the same stack:

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │ 5. OBSERVE      Endpoint Security framework · unified log · osquery │
 │                 (telemetry — nothing below emits alerts by itself)  │
 ├─────────────────────────────────────────────────────────────────────┤
 │ 4. REMEDIATE    Apple's background remediation engine (community    │
 │                 name: "XProtect Remediator") + behavioral engine    │
 ├─────────────────────────────────────────────────────────────────────┤
 │ 3. BLOCK        XProtect (YARA signatures, first-launch checks)     │
 │                 Notarization ticket revocation (fast Apple push)    │
 ├─────────────────────────────────────────────────────────────────────┤
 │ 2. PREVENT      Gatekeeper + Notarization + quarantine/provenance   │
 │    LAUNCH       SIP · TCC consent gates · MDM/DDM policy            │
 ├─────────────────────────────────────────────────────────────────────┤
 │ 1. PLATFORM     Secure Enclave · Apple silicon boot chain ·         │
 │    INTEGRITY    Signed System Volume (SSV) · FileVault              │
 └─────────────────────────────────────────────────────────────────────┘
```

The recurring theme for defenders: layers 1–4 are strong but **opaque and Apple-operated** — you configure them and read their logs; you don't extend them. Layer 5 is where your EDR, SIEM, and hunt program live, and Apple has given it exactly one sanctioned door: the Endpoint Security framework.

| What you can control | What you can only observe | What you can't touch |
|---|---|---|
| Gatekeeper policy, TCC grants (via MDM/PPPC), FileVault, update enforcement, baseline settings | XProtect detections, remediation-engine scans, notarization revocations (unified log / ES events) | XProtect signature content, remediation logic, notarization decisions — all Apple-operated |

### Milestones that shape today's defensive assumptions

| Release | Security change that still matters |
|---|---|
| **OS X 10.11 El Capitan** | SIP — root can no longer modify protected system locations |
| **macOS 10.12 Sierra** (2016) | Unified logging replaces UNIX syslog |
| **macOS 10.15 Catalina** | Read-only system volume (System/Data split); **Endpoint Security framework** replaces kexts for security telemetry |
| **macOS 11 Big Sur** | **Signed System Volume** — runtime cryptographic verification of all system content |
| **macOS 13 Ventura** | `eslogger` ships in the OS; ES gains background-task-management (login/launch item) and XProtect detection/remediation notify events |
| **macOS 15 Sequoia** | Control-click Gatekeeper override removed — unsigned/un-notarized software must be approved in System Settings |
| **macOS 26 Tahoe** | Legacy imperative MDM software-update commands **deprecated** (DDM is the path); last Intel-capable release |
| **macOS 27 Golden Gate** (2026-09-14) | Apple-silicon-only; legacy MDM software-update commands **removed** — OS update management requires DDM |

---

## Platform integrity: Secure Enclave, boot chain, SSV

### Secure Enclave

The [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web) is a dedicated secure subsystem on Apple SoCs, isolated from the application processor so that key material stays protected even if the kernel is compromised. On Mac it is present in **all Apple silicon Macs** and in Intel Macs with the **T2 chip** (plus the T1 in 2016–2017 MacBook Pro models). It anchors FileVault key handling, Touch ID, and the boot trust chain. With macOS 27 dropping Intel support entirely, a current-OS fleet has a Secure Enclave in every machine — baselines no longer need an "Intel without T2" exception lane.

### Signed System Volume (SSV) and the System/Data split

Since macOS 10.15, the OS lives on a **read-only system volume** separate from the writable **Data volume** (user and app data), joined by firmlinks into one apparent filesystem. macOS 11 added the [Signed System Volume](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web): a kernel-enforced mechanism that verifies system content integrity **at runtime**, rejecting any data — code and non-code — that lacks a valid cryptographic signature from Apple. It works as a hash hierarchy (Merkle-tree style) whose root "seal" is signed by Apple; updates are applied to APFS snapshots and the boot halts if seal verification fails.

**Defender consequences:**

| Fact | Consequence |
|---|---|
| System volume is sealed and verified at runtime | Persistent OS-file implants of the classic rootkit style are off the table on a healthy Mac; **persistence lives on the Data volume** — LaunchAgents/Daemons, login items, user config |
| Updates go through snapshots, seal re-signed by Apple | "Patch the binary in place" tampering breaks the seal; integrity failures are loud (boot halt), not silent |
| `csrutil authenticated-root disable` exists for development | A Mac running with SSV disabled is a red flag worth an inventory check (state is queryable, e.g. via osquery or `csrutil status`) |

### Boot integrity

On Apple silicon, boot proceeds from immutable Boot ROM through iBoot to the kernel with each stage verifying the next, and startup-security policy (including whether the Mac may boot older/unsigned OSes) is managed per-OS-install and protected by the Secure Enclave. Defenders mostly interact with this through MDM restrictions and through verifying fleet state, not through configuration knobs. Details: [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) (boot process sections).

---

## Execution control: SIP, Gatekeeper, notarization, quarantine

### System Integrity Protection (SIP)

[SIP](https://support.apple.com/en-us/102149) (OS X El Capitan onward) restricts **the root user itself**: root cannot modify SIP-protected files and folders (`/System`, `/usr`, `/bin`, `/sbin`, and preinstalled apps, with carve-outs like `/usr/local`), and software cannot silently select a startup disk. Only Apple-signed processes with special entitlements — Apple installers and updaters — may write to protected locations. Disabling SIP requires booting to Recovery; it is not something malware does with a root shell.

**Do**
- Treat `csrutil status` ≠ enabled as a fleet-compliance finding; every baseline (mSCP, CIS, STIG) checks it.
- Remember SIP also gates things your tools may want (task_for_pid on platform binaries, kernel extensions) — the sanctioned answers are system extensions and Endpoint Security, below.

**Don't**
- Accept "we disabled SIP to make the agent work" from any vendor in 2026. ES-based agents don't need it.

### Gatekeeper and quarantine

[Gatekeeper](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web) verifies that downloaded software is from an identified (Developer ID) developer, is notarized by Apple, and has not been altered. Regardless of how software arrived, macOS checks it for known malicious content on first open — and Gatekeeper also tracks the **provenance** of files written by downloaded software (the quarantine/provenance system behind the `com.apple.quarantine` extended attribute). Policy can be tightened to App Store-only, and user override can be restricted by device management.

The operationally important change: **since macOS Sequoia (15), users can no longer Control-click (right-click) → Open to bypass Gatekeeper** for unsigned or un-notarized software. They must explicitly approve it in **System Settings → Privacy & Security** ([Apple developer announcement, August 2024](https://developer.apple.com/news/?id=saqachfa)). Stealer campaigns that relied on walking victims through the Control-click override had to move to instructing users through the Settings pane — more friction, and a distinctive user-behavior tell.

Quarantine mechanics defenders should know:

| Mechanism | Detail |
|---|---|
| **`com.apple.quarantine` xattr** | Applied to downloads by quarantine-aware apps (browsers, mail, chat); its presence is what triggers the full Gatekeeper evaluation on first open |
| **Provenance tracking** | Gatekeeper additionally tracks files *written by* quarantined/downloaded software, so a dropper's payloads don't launder themselves clean |
| **Stripping the attribute** | Removing quarantine attributes to skip evaluation is classic tradecraft (part of **T1553.001 Gatekeeper Bypass**) — xattr changes on fresh downloads are detectable via ES file/xattr events |
| **Archive edge cases** | Quarantine propagation depends on the unpacking tool honoring it; disk images and third-party unarchivers are the historically messy path — one reason stealers ship as DMGs |

### Notarization

Notarization is Apple's automated pre-distribution malware scan for Developer ID software; the resulting ticket is stapled to the app and checked by Gatekeeper. Two defensive properties matter: it gives Apple a **choke point** (malware families distributed outside the App Store must either get notarized, steal a signing identity, or convince the user to bypass), and it is **revocable** — see the next section.

ATT&CK tracks the adversary side of this control as **T1553 Subvert Trust Controls**, with macOS sub-techniques **T1553.001 Gatekeeper Bypass** and **T1553.006 Code Signing Policy Modification**.

---

## Built-in anti-malware: XProtect, remediation, ticket revocation

Apple's [malware-protection documentation](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web) describes three layers: prevent launch (App Store review, Gatekeeper + notarization), block execution (Gatekeeper, notarization, XProtect), and remediate infections.

| Component | What it is | Update channel |
|---|---|---|
| **XProtect** | Built-in signature-based antivirus using **YARA** signatures; checks apps on first launch, when an app changes on disk, and when signatures update | Checked **daily** by default, ships independently of OS updates |
| **Remediation engine** | Apple: "an engine that remediates infections" from automatically delivered updates. The community name — **XProtect Remediator** — plus the observed behavior (24 scanning modules as counted by [Eclectic Light Company, January 2025](https://eclecticlight.co/2025/01/03/why-xprotect-remediator-scans-now-take-longer/), a list unchanged at the September 2026 v163 update; roughly daily background scans, more often for elevated threats, preferring idle-but-awake periods) comes from that third-party research, **not** Apple documentation | With XProtect data updates |
| **Behavioral engine** | Apple describes "an advanced engine to detect unknown malware based on behavioral analysis" — no public knobs or documentation beyond that sentence | Apple-operated |
| **Notarization ticket revocation** | Apple can revoke tickets of apps later found malicious; Gatekeeper then blocks them | Pushed out-of-band, much more frequently than XProtect signature updates; the CloudKit-sync delivery mechanism is community-observed, not stated on Apple's malware-protection page |

**Where defenders see it:** XProtect and remediation activity is observable in the **unified log**, and Endpoint Security emits dedicated notify events when Apple's engine detects or remediates malware (`ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED` / `..._XP_MALWARE_REMEDIATED`) — your ES-based EDR or eslogger can capture Apple's own AV verdicts. Forward these; a Mac where Apple's remediation engine fired is an incident lead, not a closed ticket.

**Don't** treat XProtect as your endpoint protection strategy. It is signature-based, Apple-curated, and aimed at broad commodity malware; it publishes no console, no coverage claims, and no SLAs. Every serious baseline pairs it with an ES-based EDR.

---

## Data protection: FileVault

[FileVault](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web) provides full-volume encryption using **AES-XTS** (Apple's current documentation does not state a key length — cite the algorithm, not a size). On Apple silicon and T2 Macs, all FileVault key handling happens **inside the Secure Enclave**; encryption keys are never exposed to the CPU. Internal volumes are always hardware-encrypted — before FileVault is enabled they are protected only by the hardware UID — so **turning FileVault on is effectively instant**: it upgrades key protection to require the user credential, rather than re-encrypting the disk.

| Practice | Detail |
|---|---|
| **Enforce via MDM** | FileVault enablement and enforcement is a standard MDM payload; every baseline requires it |
| **Escrow the recovery key** | Escrow the personal recovery key to MDM (or use an institutional key) so lockouts are recoverable and keys are auditable |
| **Removable media is different** | External/removable-media encryption does **not** use the Secure Enclave — treat external drives as a separate policy problem |
| **Evidence handling** | An unlocked, running Mac is the acquisition opportunity; see [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md) |

---

## Privacy and access control: TCC and PPPC

TCC (Transparency, Consent, and Control) is the consent subsystem behind every "AppName would like to access…" prompt: Full Disk Access, Screen Recording, Accessibility, camera, microphone, Files and Folders, and the rest. It is **per-user, per-app consent enforced by the OS**, and it gates exactly the data infostealers want (browser profiles, keychain-adjacent files, documents) and the capabilities RATs want (screen capture, accessibility control).

In fleets, TCC is managed with the **Privacy Preferences Policy Control (PPPC)** MDM payload — payload identifier `com.apple.TCC.configuration-profile-policy` ([Apple Platform Deployment](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)). It must be delivered through a device management service, requires supervision, and when multiple payloads apply, **the OS uses the more restrictive settings**. Note the deliberate asymmetry: some permissions can only be *denied* or delegated to standard-user approval by policy, not silently granted — Apple reserves certain grants for the human at the keyboard.

High-value TCC services from a security perspective (service keys per the PPPC payload documentation — check the payload reference for the current list and which services permit Allow vs. Deny-only):

| TCC service | Grants | Why attackers want it / why you audit it |
|---|---|---|
| **SystemPolicyAllFiles** (Full Disk Access) | Read access across protected user data, Mail, Messages, Safari data, Time Machine | The single most powerful grant; mandatory for EDR/ES agents, gold for stealers — every FDA holder is on the audit list |
| **Accessibility** | Synthetic input, UI control | RAT capability: click prompts, dismiss dialogs, drive the UI |
| **ScreenCapture** | Screen recording | Surveillance and credential harvesting from the screen; deny-only/standard-user-approvable by policy |
| **ListenEvent** (Input Monitoring) | Keystroke observation | Keylogging; deny-only/standard-user-approvable by policy |
| **AppleEvents** | Scripting other apps | Automation abuse — driving Terminal, Finder, or browsers through `osascript` (pairs with T1059.002) |

**Do**
- Pre-grant your EDR/ES agent **Full Disk Access** via PPPC at deployment — an ES client without FDA is blind to much of what matters.
- Audit PPPC profiles as attack surface: a profile that grants Accessibility/FDA broadly is a privilege grant, and ATT&CK tracks adversary abuse of the consent database as **T1548.006 TCC Manipulation**.
- Alert on unexpected changes to TCC state and on unusual apps acquiring high-value permissions (FDA, Screen Recording, Accessibility).

**Don't**
- Train users that TCC prompts are noise by over-prompting them with badly packaged internal tools — prompt fatigue is exactly what ClickFix-style social engineering exploits.
- Assume TCC substitutes for EDR: it constrains *sanctioned* API access; malware running as the user still executes, reads unprotected paths, and phones home without ever touching a TCC-gated resource.

---

## Fleet management: MDM and Declarative Device Management

macOS management runs through the MDM protocol, typically with Automated Device Enrollment through Apple Business Manager for corporate devices (enrollment that users can't remove). **Declarative Device Management (DDM)** extends the same protocol and enrollment: instead of the server issuing imperative commands and polling, the server declares intended state and the device enforces it locally and reports status changes itself.

DDM stopped being optional in this OS cycle: Apple **deprecated the legacy imperative software-update commands and payloads in the 26 OS cycle and removed them in the 27 cycle**, so OS software-update management on macOS 27 requires DDM (per [Microsoft Intune's migration guidance](https://techcommunity.microsoft.com/blog/intunecustomersuccess/support-tip-move-to-declarative-device-management-for-apple-software-updates/4432177); consult [Apple Platform Deployment](https://support.apple.com/guide/deployment/welcome/web) for the authoritative list of exactly which commands were deprecated versus removed).

| Management capability | Security use |
|---|---|
| **DDM software updates** | Enforced update deadlines with local enforcement — patch latency SLA without polling |
| **Configuration profiles** | Gatekeeper policy, FileVault enforcement, restrictions, login/background items visibility |
| **PPPC payload** | TCC pre-grants for security agents (above) |
| **System extension payload** | Whitelist and auto-approve your EDR's ES system extension so installation needs no user action |
| **Inventory/attestation** | OS version, SIP/FileVault state, enrolled certificate identity for zero-trust access decisions |

---

## Hardening baselines: mSCP (SP 800-219), CIS, DISA STIG

### NIST macOS Security Compliance Project (mSCP)

The [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) — a joint NIST, NASA, DISA, and LANL project (docs at [pages.nist.gov/macos_security](https://pages.nist.gov/macos_security/)) — is the reference implementation for macOS hardening: a rules catalog from which you generate baselines, compliance scripts, and configuration profiles instead of hand-maintaining checklists.

| Item | Current state (verified 2026-09-24) |
|---|---|
| **Current release** | **mSCP 2.0, Release 27.0** (published 2026-09-11) — supports macOS 27, iOS 27, and visionOS 27 from one unified main branch |
| **macOS 26 fleets** | Tahoe Guidance **Revision 3.0** (2026-06-22) |
| **2.0 changes** | Typst replaces Ruby/AsciiDoctor for PDF generation; exit-code-based rule checks; JSON compliance output |
| **Formal publication** | **NIST SP 800-219** ("Automated Secure Configuration Guidance from the macOS Security Compliance Project"); [Rev. 2 initial public draft](https://csrc.nist.gov/pubs/sp/800/219/r2/ipd) published 2026-06-22, comment period closed 2026-08-14 — cite Rev. 2 as a draft, not final guidance |
| **Official mappings** | NIST SP 800-53r5, DISA STIG, CIS Benchmarks, CIS Controls, CMMC levels, BSI indigo |
| **ATT&CK mapping** | **None exists.** mSCP does not map to ATT&CK, and Apple publishes no official control-to-ATT&CK mapping — any macOS-control-to-technique linkage you see is third-party or model-generated unless it comes from a MITRE/CTID mapping project you've verified covers macOS |

The working model: mSCP is a **rules catalog, not a single checklist**. Each rule carries a check, a fix, references, and the framework mappings above; you select a published baseline (800-53-derived, STIG, CIS-aligned) or tailor your own rule set, then generate the artifacts — human-readable guidance, a compliance-audit script (2.0 adds exit-code-based checks and JSON output for pipeline consumption), and configuration profiles for MDM deployment. Rules are organized into families covering audit, authentication, iCloud, OS behavior, password policy, and System Settings — browse the [rules directory](https://github.com/usnistgov/macos_security) for the current set per OS release.

### CIS Apple macOS Benchmark

CIS versions its macOS benchmarks per OS release, and they lag new OS launches by weeks to months. As of this writing (2026-09-24): the current release is the **CIS Apple macOS 26 Tahoe Benchmark v1.1.0** — [Tenable's audit catalog](https://www.tenable.com/audits/CIS_Apple_macOS_26_Tahoe_v1.0.0_L1) now marks its v1.0.0 audit deprecated with a v1.1.0 successor — and **no CIS benchmark for macOS 27 has been published** — community trackers expect a Tahoe v2.0 and a Golden Gate v1.0 draft around Oct–Nov 2026. Exact CIS version strings require a CIS WorkBench login to confirm — **re-verify on [cisecurity.org](https://www.cisecurity.org/benchmark/apple_os) before citing them in an audit deliverable.**

### Choosing and running a baseline

| If you are… | Use |
|---|---|
| US federal / DoD-adjacent | mSCP with the 800-53 or STIG baseline (DISA's macOS STIG is itself built through mSCP collaboration) |
| Commercial, audit-driven | CIS Level 1 (Level 2 where the ATP threat model justifies the usability cost) |
| Building your own | Generate from mSCP rules and tailor — the project exists precisely so you inherit maintained check/fix/verify logic per OS release |

**Do:** regenerate baselines each OS cycle (rules change per release); deploy enforcement via MDM profiles, verification via the compliance script or osquery; track exceptions as risk acceptances with owners.
**Don't:** run a Tahoe baseline against Golden Gate and call it compliance; hand-edit generated profiles (tailor at the rule/variable layer instead).

---

## Native telemetry: Endpoint Security, unified log, eslogger

### Endpoint Security (ES) framework

The [Endpoint Security framework](https://developer.apple.com/documentation/endpointsecurity) (macOS 10.15+) is Apple's C API for monitoring system events for potentially malicious activity — the sanctioned replacement for the kernel extensions and kauth listeners security vendors used to ship. Clients are built as **system extensions**, require the restricted `com.apple.developer.endpoint-security.client` entitlement (Apple-granted), and register for events in two modes:

| Mode | Behavior | Use |
|---|---|---|
| **AUTH events** | Client must render a verdict before the operation proceeds | Blocking/EDR prevention (e.g., authorize an `exec`) |
| **NOTIFY events** | Client is informed; no blocking | Telemetry: process executions, forks, file-system events and mounts, signals, and — on macOS 13+ — background-task-management (login/launch item) changes and XProtect detection/remediation events |

This is the single most important fact about macOS detection engineering: **if your EDR isn't an ES client, it isn't seeing kernel-mediated ground truth.** ES event delivery includes code-signing information about the instigating process, and the framework — not the vendor — decides what is observable.

Event families most relevant to detection (see the [Endpoint Security documentation](https://developer.apple.com/documentation/endpointsecurity) for the full `es_event_type_t` list, which grows with each release):

| ES event family | Examples | Detection use |
|---|---|---|
| **Process lifecycle** | `EXEC`, `FORK`, `EXIT`, `SIGNAL` | Execution chains, parent/child anomalies, agent-killing signals |
| **File system** | `OPEN`, `CREATE`, `WRITE`, `UNLINK`, `RENAME`, `MOUNT` | Persistence-path writes, staging, mass-modification (ransomware), mounted DMGs |
| **Extended attributes** | xattr set/delete events | Quarantine-attribute stripping (T1553.001) |
| **Background Task Management** (macOS 13+) | `BTM_LAUNCH_ITEM_ADD` / `..._REMOVE` | Login/launch item persistence made directly observable (T1543.001/.004, T1547.015) |
| **Apple anti-malware** | `XP_MALWARE_DETECTED`, `XP_MALWARE_REMEDIATED` | Apple's own AV verdicts in your pipeline |
| **AUTH variants** | `AUTH_EXEC`, `AUTH_OPEN`, … | Prevention: the client's verdict gates the operation |

### Unified log

The unified logging system (macOS 10.12+, replacing UNIX syslog) is the second native telemetry plane: structured, compressed, high-volume, and where Apple's own subsystems — including XProtect and remediation activity, Gatekeeper decisions, TCC, and MDM — narrate what they did.

| Task | Mechanism |
|---|---|
| Live triage | `log stream` with subsystem/predicate filters |
| Retrospective | `log show` against the live store or an archive |
| Collection | `log collect` → a `.logarchive` bundle, viewable in Console or parsed at scale (Mandiant/Google Cloud maintain an [open-source unified-log parser](https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/)) |
| Caveats | Rotation is aggressive and volume is huge — decide *before* the incident which subsystems you forward; private data redaction (`<private>`) hides fields unless profiles permit otherwise |

### eslogger

`eslogger` (shipped with macOS 13 Ventura, [introduced at WWDC22](https://developer.apple.com/videos/play/wwdc2022/110345)) taps the ES event stream from the command line and emits **JSON** to stdout or the unified log. At introduction it supported all 80 NOTIFY event types — the count has grown since; run `eslogger --list-events` on a current system rather than citing 80. It must run as root and requires Full Disk Access.

Position it honestly: the man page itself says it is not intended to be used by applications and it lacks the schema stability and integrity protection of a native ES client. **eslogger is a superb investigation, triage, and detection-prototyping tool — not a production sensor.**

---

## Extending visibility: osquery and detection/response tooling

### osquery on macOS

[osquery](https://github.com/osquery/osquery/releases) (current stable **5.23.1**, published 2026-06-24) exposes endpoint state as SQL tables and is widely used for macOS fleet visibility — answering the *state* questions ES streams don't: what's installed, what persists, what's configured.

| Question | osquery angle |
|---|---|
| What persists on this fleet? | Launch daemons/agents, login items, cron, kernel/system extensions tables |
| Is the platform intact? | SIP status, Gatekeeper status, FileVault/disk-encryption state, OS version drift |
| What's on disk / who signed it? | Apps inventory, code-signature tables, quarantine-attribute queries |
| Event streams | osquery ships ES-backed event tables (process events and more) — confirm exact table names and requirements in the [schema docs](https://osquery.io/schema/) for your deployed version |
| Baseline verification | mSCP-style checks expressed as scheduled queries feeding your SIEM |

Representative posture queries (long-stable tables — still verify column names against the schema for your deployed version):

```sql
-- Is the platform intact?
SELECT config_flag, enabled FROM sip_config;
SELECT assessments_enabled, dev_id_enabled FROM gatekeeper;
SELECT name, encrypted, type FROM disk_encryption;

-- What persists, and what extends the system?
SELECT label, program, program_arguments FROM launchd
  WHERE run_at_load = '1' AND path NOT LIKE '/System/%';
SELECT identifier, version, state, category FROM system_extensions;
```

### The macOS detection/response stack

| Layer | Sanctioned mechanism | Notes |
|---|---|---|
| **EDR** | ES-client system extension | The entire commercial macOS EDR market runs on ES; evaluate vendors on which AUTH/NOTIFY events they consume and what they do with Apple's XP malware events |
| **Binary authorization** | ES AUTH exec events | Santa (open-source, originally Google, now maintained by North Pole Security) is the reference allow/deny-listing implementation |
| **Fleet state** | osquery + a fleet manager | Pair with MDM inventory for coverage cross-checks |
| **Log pipeline** | Unified log forwarding + ES JSON | Get XProtect/remediation, Gatekeeper, TCC, and auth subsystems into the SIEM — see [SIEM Reference](SIEM_REFERENCE.md) |
| **Network** | NetworkExtension framework (content filter / DNS proxy) | The sanctioned network-visibility path on modern macOS; kernel network extensions are gone |
| **Detection content** | [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Data Components](ATTACK_DATA_COMPONENTS.md) | Filter to macOS-platform techniques and map each to ES event / unified-log subsystem before declaring coverage |

---

## macOS in MITRE ATT&CK v19

Version facts first, because they are perishable: MITRE ATT&CK is currently **v19.2** — its first "Agile" release (August 2026, updating Groups/Software/Campaigns); v19 proper was released 2026-04-28 ([version history](https://attack.mitre.org/resources/versions/)). The headline structural change in v19: **the Defense Evasion tactic was split into Stealth (TA0005) and Defense Impairment (TA0112)** ([v19 release notes](https://attack.mitre.org/resources/updates/updates-april-2026/)). Any macOS coverage matrix still showing "Defense Evasion" is pre-v19. Enterprise v19 totals: 15 tactics, 222 techniques, 475 sub-techniques, 44 mitigations, 697 detection strategies, 1,758 analytics, 106 data components. **v20 is expected around late October 2026** on the biannual cadence — recheck all counts then.

The [Enterprise macOS platform matrix](https://attack.mitre.org/matrices/enterprise/macos/) (content v19.2) displays **13 tactics and 154 parent techniques**. Per-tactic counts below sum to more than 154 because techniques appear under multiple tactics; sub-techniques are additional; Reconnaissance and Resource Development are not part of platform matrices.

| Tactic | macOS techniques | Where defenders get telemetry |
|---|--:|---|
| **Initial Access** | 10 | Quarantine/provenance attributes, Gatekeeper decisions (unified log), ES file/exec events, mail/browser logs |
| **Execution** | 11 | ES exec/fork events (with signing info), unified log; interpreters — `osascript`, shells — are the hot spot |
| **Persistence** | 17 | ES file events on LaunchAgents/LaunchDaemons paths, ES BTM launch-item events (macOS 13+), osquery persistence tables |
| **Privilege Escalation** | 10 | ES exec/auth events, unified log authorization subsystem, sudo logs |
| **Stealth** | 19 | ES file/xattr events (quarantine stripping), unified log gaps, code-signing anomalies in ES metadata |
| **Defense Impairment** | 9 | ES events on agent processes/config, TCC state changes, unified log |
| **Credential Access** | 15 | ES open events on keychain and browser-profile paths, TCC denials, `security` CLI invocations in ES exec events |
| **Discovery** | 26 | ES exec events — discovery is almost entirely command-line visible (`system_profiler`, `dscl`, `sw_vers`, …) |
| **Lateral Movement** | 7 | Unified log (sshd, screen sharing), ES exec events |
| **Collection** | 14 | TCC grants (screen/audio/files), ES file-open patterns, clipboard/screen APIs |
| **Command and Control** | 18 | NetworkExtension filters, DNS logs, proxy/firewall — ES is not a network sensor |
| **Exfiltration** | 8 | Network telemetry; ES file events for staging/archiving |
| **Impact** | 15 | ES file-modification bursts (encryption), unified log |

Selected macOS techniques worth building detections around first (IDs, names, and macOS platform verified in this library's [`data/attack/technique_profiles.jsonl`](data/attack/technique_profiles.jsonl) — a pre-v19 ATT&CK snapshot that predates the Stealth/Defense-Impairment split — and re-checked against attack.mitre.org v19.2):

| Technique | Why it matters on macOS |
|---|---|
| **T1543.001 / T1543.004** Launch Agent / Launch Daemon | The canonical persistence pair; watch writes to `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` |
| **T1547.015** Login Items · **T1647** Plist File Modification | The rest of the persistence surface; BTM events made login-item changes observable |
| **T1553.001** Gatekeeper Bypass · **T1553.006** Code Signing Policy Modification | Attacks on the execution-control layer itself, incl. quarantine-attribute stripping |
| **T1548.006** TCC Manipulation | Attacks on the consent layer; pairs with auditing PPPC profiles |
| **T1555.001** Keychain · **T1555.003** Credentials from Web Browsers | The infostealer core loop |
| **T1059.002** AppleScript · **T1059.004** Unix Shell | `osascript` prompting for passwords is a classic stealer move; ES exec events carry full context |
| **T1070.002** Clear Linux or Mac System Logs | Anti-forensics against the unified log (v19 added new sub-techniques under this lineage) |
| **T1574.004** Dylib Hijacking | macOS-specific hijack of library search order — new coverage emphasized in v19 |
| **T1562.001** Disable or Modify Tools · **T1518.001** Security Software Discovery | Defense Impairment / recon against your EDR footprint |

**No official Apple-control-to-ATT&CK mapping exists** — neither from Apple nor in mSCP. The table above links techniques to *telemetry sources*, which is a defender's judgment call, not an official mapping.

---

## macOS threat landscape (taxonomy level)

Descriptive, per public vendor and Apple documentation — prevalence figures are **vendor-reported**, not neutral measurements.

| Category | Description | Representative public reporting |
|---|---|---|
| **Infostealers** | The leading current crimeware concern in vendor reporting: one-shot theft of keychain data, browser credentials/cookies, crypto wallets, and documents, typically via trojanized DMG installers and ClickFix-style social engineering (fake fixes/CAPTCHAs walking the user through executing the payload themselves). Families named in vendor reporting: **Atomic macOS Stealer (AMOS)**, **DigitStealer**, **MacSync** ([Microsoft Security, 2026-02-02](https://www.microsoft.com/en-us/security/blog/2026/02/02/infostealers-without-borders-macos-python-stealers-and-platform-abuse/)); **CrashStealer**, which poses as Apple's crash-reporting tool ([Jamf Threat Labs, July 2026](https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/)), and **AmnesiaStealer** ([Jamf Threat Labs, August 2026](https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/)); Jamf also reported AMOS detections jumping roughly 300% in a single month by August 2025 ([vendor figure](https://www.jamf.com/blog/macpaw-macos-malware-evolution-amos-stealer-cybercrime-ecosystem/)) |
| **Adware / bundleware** | Historically the most common macOS PUP category: browser hijacking, ad injection, and pay-per-install bundling riding on freeware installers — commercially motivated, TOS-gray, and the reason "first malware layer" tuning matters |
| **Backdoors / RATs** | Lower volume, targeted use (including against developers and crypto/finance targets per public vendor reporting); rely on the same persistence surface (launch items) and TCC-gated capabilities described above |

Delivery patterns named repeatedly in public advisories, and the control each one collides with:

| Delivery pattern | Platform control it must defeat | Defender leverage |
|---|---|---|
| **Trojanized DMG/PKG installers** (malvertising, SEO poisoning, cracked software) | Gatekeeper + notarization | Post-Sequoia, the user must walk to System Settings to run it — that approval is loggable and coachable |
| **ClickFix-style prompts** (fake fix/verification pages instructing the user to paste and run commands) | Everything — the user executes the payload themselves | ES exec telemetry on shell/`osascript` spawned from browser-adjacent contexts; user education |
| **Fake password dialogs** (`osascript` prompts, fake system UI) | Keychain/TCC consent | ES exec events on `osascript` with dialog arguments; T1059.002 detections |
| **Stolen/abused developer identities** | Notarization trust | Apple ticket revocation, pushed fast and out-of-band (community-observed as CloudKit-synced); track revocation events in the unified log |

**The pattern to internalize:** current macOS crimeware mostly *asks the user to defeat the platform* — approve the unsigned app in System Settings, type a password into an `osascript` dialog, paste a command into Terminal — because the layered controls made silent compromise expensive. That makes user-visible control friction (the Sequoia Gatekeeper change), TCC grant auditing, and ES-based detection of the ask-the-user patterns disproportionately valuable. Family specifics belong in [Malware Families](MALWARE_FAMILIES.md) — note its macOS stealer coverage (AMOS, CrashStealer, AmnesiaStealer) is still to be written as of 2026-09-24; this doc stays at taxonomy level deliberately.

---

## Defender's checklist

**Platform (verify, don't assume)**
- [ ] SIP enabled fleet-wide; SSV seal intact; alert on exceptions
- [ ] FileVault enforced via MDM; recovery keys escrowed and access-audited
- [ ] OS currency via DDM-enforced update deadlines (mandatory for macOS 27 update management); macOS 26 is the only supported Intel lane left — plan its exit

**Policy**
- [ ] Gatekeeper at default or stricter; user override restricted by MDM where the population allows
- [ ] Baseline generated from mSCP (or CIS) **for the exact OS version deployed**, enforced via profiles, verified via compliance script/osquery
- [ ] PPPC: security agents pre-granted FDA; all other PPPC grants reviewed as privilege

**Telemetry**
- [ ] EDR is an ES client, auto-approved via MDM system-extension payload, with FDA
- [ ] Apple's XP malware detected/remediated events and Gatekeeper/TCC unified-log subsystems forwarded to the SIEM
- [ ] osquery (or equivalent) answering persistence/state questions on schedule
- [ ] Network visibility via NetworkExtension-based filtering or DNS logging

**Detection program**
- [ ] macOS techniques from the table above mapped to a concrete event source each — a technique with no macOS event source is a *known gap*, recorded as such
- [ ] eslogger in the IR toolkit for on-box triage; `.logarchive` collection in the IR runbook
- [ ] Vendor coverage claims tested against macOS specifically (see [Purple Team](PURPLE_TEAM_REFERENCE.md)) — Windows detection parity is not implied

---

## Sources

Accessed 2026-09-24. The Apple Platform Security Guide is continuously updated with no version numbers (current PDF edition dated August 2026) — cite section URLs with an access date.

| Source | Content |
|---|---|
| [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) | Canonical architecture reference |
| [Protecting against malware](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web) · [Gatekeeper](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web) · [SSV](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web) · [FileVault](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web) · [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web) · [SIP](https://support.apple.com/en-us/102149) | Apple, per control |
| [PPPC payload](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web) | Apple Platform Deployment (TCC management) |
| [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) · [WWDC22 eslogger session](https://developer.apple.com/videos/play/wwdc2022/110345) · [Gatekeeper change in Sequoia](https://developer.apple.com/news/?id=saqachfa) | Apple developer documentation |
| [ATT&CK versions](https://attack.mitre.org/resources/versions/) · [v19 release notes](https://attack.mitre.org/resources/updates/updates-april-2026/) · [macOS matrix](https://attack.mitre.org/matrices/enterprise/macos/) | MITRE ATT&CK v19.2 facts and counts |
| [mSCP GitHub](https://github.com/usnistgov/macos_security) · [project docs](https://pages.nist.gov/macos_security/) · [SP 800-219 Rev. 2 IPD](https://csrc.nist.gov/pubs/sp/800/219/r2/ipd) | NIST mSCP and its formal publication |
| [CIS Apple macOS benchmarks](https://www.cisecurity.org/benchmark/apple_os) · [Tenable audit catalog (Tahoe — v1.0.0 page, deprecated in favor of v1.1.0)](https://www.tenable.com/audits/CIS_Apple_macOS_26_Tahoe_v1.0.0_L1) | CIS baseline status |
| [osquery releases](https://github.com/osquery/osquery/releases) | osquery 5.23.1 |
| [Microsoft Security Blog (2026-02-02)](https://www.microsoft.com/en-us/security/blog/2026/02/02/infostealers-without-borders-macos-python-stealers-and-platform-abuse/) · Jamf Threat Labs: [CrashStealer (2026-07)](https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/) · [AmnesiaStealer (2026-08)](https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/) · [AMOS surge (2025-09)](https://www.jamf.com/blog/macpaw-macos-malware-evolution-amos-stealer-cybercrime-ecosystem/) | Vendor threat reporting (stealers) |
| [Eclectic Light Company (2023-02-25)](https://eclecticlight.co/2023/02/25/what-are-those-xprotects/) · [module count (2025-01-03)](https://eclecticlight.co/2025/01/03/why-xprotect-remediator-scans-now-take-longer/) · [XPR v163 (2026-09-18)](https://eclecticlight.co/2026/09/18/apple-has-released-an-update-to-xprotect-remediator-5/) | Third-party XProtect Remediator research (naming, module count, cadence) |
| [Mandiant unified-log analysis](https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/) · [Intune DDM guidance](https://techcommunity.microsoft.com/blog/intunecustomersuccess/support-tip-move-to-declarative-device-management-for-apple-software-updates/4432177) · [macOS 27 release (9to5Mac)](https://9to5mac.com/2026/09/09/apple-confirms-macos-27-golden-gate-launch-date-september-14/) | Telemetry tooling, DDM migration, release timing |

**Verification notes:** "XProtect Remediator" as a name, its 24-module count (Eclectic Light, 2025-01-03; module list unchanged at the 2026-09-18 v163 update), and its scan cadence are third-party observations (Eclectic Light), not Apple documentation; the CloudKit delivery channel for notarization ticket revocation is likewise community-observed, not stated on Apple's malware-protection page. FileVault key length is deliberately omitted — Apple's current page states only AES-XTS. CIS exact version strings were confirmed via a secondary catalog (Tenable), not CIS WorkBench. eslogger's 80-event figure is its macOS 13 introduction count. ATT&CK counts are v19.2; v20 is expected ~October 2026. Technique IDs cited were verified against this library's `technique_profiles.jsonl` — a pre-v19 (v18-era) ATT&CK snapshot — and re-checked against attack.mitre.org v19.2.

---

*macOS, Gatekeeper, FileVault, and related marks are trademarks of Apple Inc.; MITRE ATT&CK® is a trademark of The MITRE Corporation; CIS Benchmarks™ are published by the Center for Internet Security. This is an independent practitioner reference, not affiliated with or endorsed by Apple, MITRE, NIST, or CIS — consult the linked primary sources for authoritative and current guidance.*
