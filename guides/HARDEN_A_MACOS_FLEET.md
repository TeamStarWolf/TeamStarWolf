# Harden a macOS Fleet with mSCP

> **By the end of this guide you will have a NIST-derived security baseline enforced on every Mac you manage, a compliance script proving it, and Endpoint Security telemetry flowing into your SIEM.** This is for defenders who run Macs at work — MDM admins, security engineers, and compliance leads — not just federal shops. If you can drive an MDM console and a terminal, you can do this.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 1–2 days for a pilot cohort; 2–4 weeks to full fleet | Intermediate | An MDM-enrolled Mac fleet, one admin Mac on the target OS, a SIEM ingest path | A tailored baseline YAML, signed configuration profiles + DDM assets, a compliance script with fleet-wide audit results, and an ES telemetry pipeline |

## Before you start

- [ ] Read the platform picture first — which controls exist, what a baseline actually configures, and where the telemetry lives: [MACOS_SECURITY_REFERENCE.md](/MACOS_SECURITY_REFERENCE.md)
- [ ] A fleet enrolled in MDM, ideally via Automated Device Enrollment, so profiles land without user action: [Apple Platform Deployment](https://support.apple.com/guide/deployment/welcome/web)
- [ ] One admin/test Mac running the exact OS version you are hardening — baselines are per-release, not portable
- [ ] A container runtime on that Mac — [Apple Container](https://github.com/apple/container) (recommended by the project) or [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/) — or Python 3.12+ if you prefer the local path: [mSCP project docs](https://pages.nist.gov/macos_security/)
- [ ] Know which framework you answer to (800-53, CMMC, CIS, STIG) — mSCP ships baselines mapped to each: [GRC_COMPLIANCE_REFERENCE.md](/GRC_COMPLIANCE_REFERENCE.md)
- [ ] A SIEM or log pipeline that can take JSON and unified-log output: [SIEM_REFERENCE.md](/SIEM_REFERENCE.md)

## Step 1 — Pick the baseline that matches your obligations

mSCP is a rules catalog, not a single checklist. Every rule carries a check, a fix, references, and mappings to NIST SP 800-53r5, DISA STIG, CIS Benchmarks and Controls, and CMMC — you pick a published baseline or tailor your own, and the tooling generates everything else.

Choose by obligation, not taste:

| If you are… | Start from |
|---|---|
| US federal / DoD-adjacent | The 800-53r5 baseline at your impact level (low/moderate/high), or the STIG baseline — DISA's macOS STIG is itself built through mSCP collaboration |
| Commercial, audit-driven | The CIS Level 1 baseline (Level 2 only where the threat model justifies the usability cost) |
| Building your own | Any of the above as a starting point, then tailor in Step 3 — you inherit maintained check/fix/verify logic per OS release |

Also decide **now** which Macs get which baseline. Mixed fleets (developer Macs vs. kiosk Macs) usually mean one tailored baseline per population, each generated from the same rules catalog.

**Checkpoint:** You can name the baseline you're deploying, the framework it satisfies, and which device population it applies to.

**Watch out:** Baselines are versioned per OS release. A macOS 26 (Tahoe) baseline run against macOS 27 (Golden Gate) is not compliance — it's a category error. Regenerate every OS cycle.

## Step 2 — Set up the mSCP tooling

mSCP 2.0 ships as a container image, which is the least-friction path — no dependency wrangling. On your admin Mac:

```bash
mkdir -p ~/Desktop/mscp/custom
container run -it \
  --volume ~/Desktop/mscp:/mscp/build \
  --volume ~/Desktop/mscp/custom:/mscp/custom \
  ghcr.io/usnistgov/mscp_2.0:latest
```

That uses Apple's `container` tool; Docker works too, but per the project docs it requires full paths in the volume mounts instead of `~` shortcuts. The two mounts matter: everything the tooling generates lands in `~/Desktop/mscp` on your Mac, and your tailored files live in `~/Desktop/mscp/custom` where they survive container restarts.

Prefer no container? Clone [usnistgov/macos_security](https://github.com/usnistgov/macos_security), create a Python 3.12+ virtual environment, and `pip3 install -r requirements.txt`. mSCP 2.0 lives on the single unified `main` branch (per-OS branches are the legacy 1.0 layout), and PDF generation now uses Typst, installed as a Python dependency — no Ruby toolchain.

**Checkpoint:** Inside the container (or your venv), `./mscp.py baseline -l` prints the list of available baseline keys.

**Watch out:** Apple's `container` tool has its own hardware and OS requirements — check the [project README](https://github.com/apple/container) before assuming it runs on your admin Mac. Docker is the fallback.

## Step 3 — Generate and tailor your baseline

Generate the baseline YAML for the key you chose in Step 1:

```bash
./mscp.py baseline -k 800-53r5_moderate
```

For a real deployment, add `-t` to tailor interactively:

```bash
./mscp.py baseline -k 800-53r5_moderate -t
```

Tailoring lets you include or exclude specific rules and set organization-defined values (ODVs) — password length, session timeout, and similar knobs — without touching the rules themselves. Add `-c` to print the 800-53 controls the baseline covers, which is the artifact your assessor will ask for. The tailored YAML lands under your `custom/` mount (`config/custom/baselines/` in a local checkout), and its filename carries an OS-version suffix — e.g. `800-53r5_moderate_macos_27.0.yaml`.

Record every rule you exclude, why, and who owns the risk. That list *is* your exceptions register — auditors will ask for it before they ask for anything else.

**Checkpoint:** A baseline YAML exists under `custom/baselines/`, your ODVs are set, and every excluded rule has a documented owner.

**Watch out:** Tailor at the rule and ODV layer, never by hand-editing the generated profiles later. Hand-edited output is overwritten on the next generation and invisible to the audit trail.

## Step 4 — Generate the guidance, profiles, and compliance script

One command turns the baseline into every artifact you need:

```bash
./mscp.py guidance custom/baselines/BASELINE_NAME.yaml -A
```

`-A` generates all outputs. To pick them individually: `-s` builds the compliance script, `-p` the configuration profiles (add `--consolidated-profile` for a single combined profile), `-d` the Declarative Device Management components, `-x` an Excel spreadsheet for the audit binder, and running with no flags produces the human-readable guidance documents (.adoc, .html, .pdf).

Everything lands in `build/BASELINE_NAME/` (your `~/Desktop/mscp` mount): `mobileconfigs/` holds the profiles, `activations/` the DDM components, `preferences/` the audit plist, and `BASELINE_NAME_compliance.sh` is the verification script for Step 6.

**Checkpoint:** `build/BASELINE_NAME/` contains mobileconfigs, DDM activations, the compliance script, and guidance documents you can hand to a reviewer.

**Watch out:** Unsigned profiles are editable in transit and look unprofessional in an MDM console. Use `-H` with your signing certificate to sign the configuration profiles at generation time.

## Step 5 — Deploy through MDM, pilot first

Upload the generated `.mobileconfig` files (or the consolidated profile) to your MDM and scope them to a pilot group — a handful of Macs that mirror your real populations — before any fleet-wide push.

Deploy alongside the baseline, in the same change window:

- **System extension payload** — auto-approve your EDR's Endpoint Security extension so installation needs no user action.
- **PPPC payload** (`com.apple.TCC.configuration-profile-policy`) — pre-grant your EDR/ES agent Full Disk Access. An ES client without FDA is blind to much of what matters. See [Apple's PPPC payload reference](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web).
- **DDM software-update enforcement** — on macOS 27 the legacy imperative MDM update commands are gone; OS update management requires DDM. The `activations/` output from Step 4 is built for this.

Let the pilot soak for at least a week of real work. You are hunting for the rule that breaks a developer tool, a conference-room Mac, or a screen-sharing workflow — cheaper to find in ten machines than a thousand.

**Checkpoint:** Pilot Macs show the profiles as installed and verified in your MDM console, and pilot users are still doing their jobs.

**Watch out:** When multiple PPPC payloads apply, macOS uses the **more restrictive** settings — a broad legacy PPPC profile already in your MDM can silently fight the new one. Audit existing profiles for overlap before you deploy, and treat every PPPC grant as a privilege grant (adversary abuse of the consent database is tracked as ATT&CK T1548.006).

## Step 6 — Verify with the compliance script

Profiles say what you *pushed*; the compliance script says what is *true*. On a pilot Mac:

```bash
sudo ./build/BASELINE_NAME/BASELINE_NAME_compliance.sh --check
```

The script must run as root and under zsh (running it with `sh` or `bash` errors out). Run without flags for an interactive menu; automate with `--check` (scan only), `--stats` (pass/fail counts from the last scan), `--compliant` / `--non_compliant` (counts for dashboards), `--fix` (remediate locally), `--cfc` (check-fix-check in one pass), and `--reset` / `--reset-all` to clear stored results. Results persist in `/Library/Preferences/org.BASELINE_NAME.audit.plist`, with a human-readable log at `/Library/Logs/BASELINE_NAME_baseline.log`.

Then operationalize it: deploy the script fleet-wide via MDM, schedule `--check` runs, and ship the plist/log results to your reporting pipeline. mSCP 2.0's exit-code-based checks and JSON output exist precisely so pipelines can consume them. For continuous state questions between scans, osquery covers the same ground (SIP status, Gatekeeper, FileVault, profiles) as scheduled queries — see [MACOS_SECURITY_REFERENCE.md](/MACOS_SECURITY_REFERENCE.md) for ready-made posture queries.

**Checkpoint:** `--stats` on a pilot Mac reports the compliance percentage you expect, failures are explained (exempt, MDM-managed, or genuinely broken), and results flow off-box.

**Watch out:** Run `--check` and read the results before you ever run `--fix` — fix mode changes live settings. And not every rule has a local fix: settings owned by configuration profiles must be remediated through MDM, so a "failed" rule may mean a profile didn't land, not that the script needs to fix it. Exemptions are honored via MDM-managed preferences, so route exceptions through that mechanism rather than editing the script.

## Step 7 — Wire Endpoint Security telemetry into the SIEM

A hardened Mac that nobody watches is a checkbox, not a defense. The Endpoint Security (ES) framework is Apple's one sanctioned door for kernel-mediated security telemetry — if your EDR is not an ES client, it is not seeing ground truth.

Three feeds, in priority order:

1. **Your ES-based EDR** (deployed in Step 5 with its system extension and FDA). Confirm which event families it forwards: process lifecycle (exec/fork/exit), file events on persistence paths (`~/Library/LaunchAgents`, `/Library/LaunchDaemons`), xattr events (quarantine stripping — ATT&CK T1553.001), and Background Task Management login/launch-item events (T1543.001/.004).
2. **Apple's own anti-malware verdicts.** ES emits `XP_MALWARE_DETECTED` and `XP_MALWARE_REMEDIATED` notify events when XProtect's remediation engine acts. Forward these and alert on them — a Mac where Apple's remediation fired is an incident lead, not a closed ticket.
3. **Unified log subsystems** for Gatekeeper decisions, TCC changes, and MDM activity, forwarded per your collector's subsystem filters. Decide which subsystems you forward *before* an incident; rotation is aggressive.

For prototyping detections and on-box triage, `eslogger` (built into macOS 13+) taps the same ES stream from the command line:

```bash
sudo eslogger --list-events
sudo eslogger exec | jq -r '.event.exec.target.executable.path'
```

It emits JSON Lines to stdout, must run as root, and the responsible process (e.g., Terminal) needs Full Disk Access — grant it under System Settings → Privacy & Security → Full Disk Access.

**Checkpoint:** A test execution on a pilot Mac (e.g., launching an unsigned test script) appears in your SIEM with process, signing, and parent context — and you can query it.

**Watch out:** eslogger is an investigation and prototyping tool, not a production sensor — Apple's own man page says it is not intended for applications, and it lacks the schema stability of a native ES client. Prototype with it, then implement in your EDR or a proper ES client.

## Step 8 — Make it repeat every OS cycle

Hardening decays. Put these on the calendar:

- **Every macOS release:** pull the current mSCP release, regenerate the baseline and all artifacts (rules change per release), re-pilot, redeploy. mSCP 2.0's unified main branch supports multiple OS versions from one checkout.
- **Every month:** review compliance-script fleet stats for drift; investigate Macs that fell out of compliance rather than silently re-fixing them.
- **Every quarter:** re-review the exceptions register and PPPC grants; retire exceptions whose reason expired.
- **Continuously:** validate that detections built on Step 7 telemetry still fire — technique-level test IDs and safe validation workflow live in [PURPLE_TEAM_REFERENCE.md](/PURPLE_TEAM_REFERENCE.md).

**Checkpoint:** Baseline regeneration is a scheduled task with an owner, not tribal knowledge — and the last run's date is written down.

## What good looks like

- Every managed Mac carries the current baseline's profiles, and the MDM console proves installation — with zero hand-edited profiles anywhere.
- Scheduled compliance-script runs report fleet-wide pass rates, and every failing rule is either an owned exception or an open ticket.
- Your EDR is an ES client with FDA, auto-approved via MDM, and its events — plus Apple's `XP_MALWARE_*` verdicts and Gatekeeper/TCC log subsystems — land in the SIEM within minutes.
- SIP, FileVault, and Gatekeeper state are continuously verified (compliance script or osquery), and an exception raises an alert, not a shrug.
- You can hand an assessor the guidance PDF, the controls mapping, the exceptions register, and last week's compliance stats without preparing anything.

## Go deeper

**In this library:**

- [MACOS_SECURITY_REFERENCE.md](/MACOS_SECURITY_REFERENCE.md) — the full platform architecture: SIP, Gatekeeper, TCC, XProtect, ES, and the baseline landscape this guide operationalizes
- [ENDPOINT_SECURITY_REFERENCE.md](/ENDPOINT_SECURITY_REFERENCE.md) — EDR architecture and evaluation criteria across platforms
- [SIEM_REFERENCE.md](/SIEM_REFERENCE.md) — building the ingest and detection pipeline the telemetry feeds
- [THREAT_INFORMED_DEFENSE_REFERENCE.md](/THREAT_INFORMED_DEFENSE_REFERENCE.md) — turning ATT&CK coverage questions into a defensive program
- [ATTACK_TECHNIQUE_ATLAS.md](/ATTACK_TECHNIQUE_ATLAS.md) — technique lookups for the macOS detections you build on this telemetry
- [CONTROLS_MAPPING.md](/CONTROLS_MAPPING.md) — how control frameworks map to techniques and mitigations

**Official sources:**

- [mSCP project documentation](https://pages.nist.gov/macos_security/) — the authoritative usage docs for every command in this guide
- [usnistgov/macos_security on GitHub](https://github.com/usnistgov/macos_security) — the rules catalog, releases, and issue tracker
- [NIST SP 800-219 Rev. 2 (draft)](https://csrc.nist.gov/pubs/sp/800/219/r2/ipd) — the formal publication behind mSCP (cite Rev. 1 as final, Rev. 2 as draft)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) — what the controls you just configured actually do

---

*Guides are procedures, not gospel — mSCP flags, baseline keys, and OS behavior change between releases. Verify every command against the current official documentation before you run it in production.*
