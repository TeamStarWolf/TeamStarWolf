# Harden a Windows Baseline

> **By the end of this guide you will have a Windows 11 / Windows Server fleet running an industry-standard security baseline — applied through GPO or Intune, with ASR rules enforced, Sysmon and command-line auditing feeding your SIEM, unique local admin passwords via LAPS, and a scanner report proving it.** Written for sysadmins and security engineers who own Windows endpoints and want a defensible, repeatable hardening process rather than a pile of one-off registry tweaks.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| Half a day for a pilot; 2–4 weeks to full production | Intermediate | Domain Admin (or Intune Endpoint Security Manager) rights, a pilot OU or device group, GPMC/RSAT | A deployed baseline, enforced ASR rules, Sysmon + 4688 telemetry, LAPS, a compliance scan report, and an exception register |

## Before you start

- [ ] Read the library's three Windows hardening references — this guide operationalizes them: [WINDOWS_HARDENING.md](/WINDOWS_HARDENING.md), [WINDOWS_HARDENING_GPO.md](/WINDOWS_HARDENING_GPO.md), [WINDOWS_HARDENING_REFERENCE.md](/WINDOWS_HARDENING_REFERENCE.md)
- [ ] A pilot scope you can afford to break: one OU of test machines (GPO) or one Entra device group (Intune) — never start with Domain Controllers
- [ ] [Microsoft Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319) downloaded (baselines + LGPO.exe + Policy Analyzer)
- [ ] A free account at [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) so you can download the benchmark PDF for your OS versions
- [ ] Group Policy Management Console with an up-to-date [ADMX Central Store](https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/create-and-manage-central-store), or access to the [Microsoft Intune admin center](https://intune.microsoft.com)
- [ ] Microsoft Defender Antivirus in **active** mode on target devices (ASR rules do not function when a third-party AV is primary — see [requirements](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview))

## Step 1 — Pick your baseline standard

Choose one primary standard and treat the other as a cross-check:

- **CIS Benchmarks** — per-OS, per-role profiles. Start with **Level 1** (security with minimal breakage); **Level 2** is defense-in-depth and will break things — adopt it control-by-control. Pick the benchmark matching each role: Windows 11 Enterprise, Server 2022/2025 Member Server, Server Domain Controller.
- **Microsoft Security Baselines** (in the SCT you downloaded) — ready-made GPO backups for Windows 11 (21H2–24H2), Server 2016–2025, Microsoft 365 Apps, and Edge. Faster to deploy because they ship as importable GPOs; Microsoft's additions over CIS include VBS with UEFI lock, Script Block Logging, and full AutoPlay/AutoRun disablement.

A sane default: deploy the Microsoft baseline as your enforced floor, then layer the CIS Level 1 deltas your compliance framework demands. The [WINDOWS_HARDENING.md](/WINDOWS_HARDENING.md) compliance mapping table shows how the two overlap per control area.

**Checkpoint:** You have a written decision — which standard, which profile (L1/L2, member server vs DC), which OS versions — and the benchmark PDF plus SCT baseline folders on disk.

**Watch out:** Do not mix both standards' password/lockout policies in one domain. Account policies apply once at the domain root; pick one source of truth for them (the [WINDOWS_HARDENING_GPO.md](/WINDOWS_HARDENING_GPO.md) GPO hierarchy section shows the recommended layout).

## Step 2 — Stage a pilot and snapshot current state

1. Create the pilot: a `Workstations-Pilot` OU with 5–20 representative machines (GPO), or a pilot Entra device group (Intune). Include your weirdest line-of-business apps — those are what baselines break.
2. Snapshot what you have so you can diff and roll back:

```powershell
# Resultant Set of Policy report for a pilot machine
gpresult /h C:\Reports\rsop-before.html

# Export current local policy as a GPO backup (LGPO.exe from the SCT)
.\LGPO.exe /b C:\Reports\GPO-Backup-Before
```

3. Open **Policy Analyzer** (also in the SCT), add the Microsoft baseline's `.PolicyRules` file, and select **Compare to Effective State**. The diff of local policy + registry against the baseline is your gap list and your work plan.

**Checkpoint:** You have `rsop-before.html`, a local-policy backup, and a Policy Analyzer diff showing exactly which settings the baseline will change.

**Watch out:** Skipping the snapshot means that when something breaks in three weeks, you can't tell whether the baseline caused it. The backup also gives you a tested rollback path.

## Step 3 — Apply the baseline via GPO or Intune

**GPO path (domain-joined):**

1. In GPMC, create an empty GPO per layer — e.g. `SEC - Baseline - Computer`, following the layered structure in [WINDOWS_HARDENING_GPO.md](/WINDOWS_HARDENING_GPO.md) (account policies at domain root; OS hardening, Defender, and role-specific GPOs per OU).
2. Right-click the new GPO > **Import Settings** and point the wizard at the matching GPO backup folder inside the baseline package (each Microsoft baseline download ships its GPO backups plus documentation and install scripts).
3. Link the GPO to the pilot OU only. On a pilot machine:

```powershell
gpupdate /force
gpresult /h C:\Reports\rsop-after.html
```

**Standalone / non-domain machines:** apply the same backup locally with `LGPO.exe /g ".\GPOs\{GUID-of-baseline}"`.

**Intune path (cloud-managed):** In the [Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Security baselines**, select the **Security Baseline for Windows 10 and later**, then **Create policy**. Review every setting group on the **Configuration settings** tab, assign to the pilot *device* group, and create.

**Checkpoint:** `rsop-after.html` (or the Intune per-device status under the baseline profile) shows the baseline applied, and pilot users can still log on, print, and run their business apps.

**Watch out:** Never edit the imported baseline GPO to carve out exceptions. Put deviations in a separate, higher-precedence `SEC - Exceptions` GPO so baseline upgrades stay a clean re-import — and each exception is visible in one place for Step 8.

**Watch out:** If a machine is both domain-joined and Intune-managed, Group Policy wins conflicts by default; co-managing the same settings from both sides produces flapping configuration. Pick one management plane per setting area.

## Step 4 — Enable ASR rules in audit mode

Attack Surface Reduction rules block the malware behaviors — Office spawning child processes, obfuscated scripts, LSASS credential theft — that map to ATT&CK techniques like T1059, T1566, and T1003.001. Full rule table with GUIDs: [WINDOWS_HARDENING.md](/WINDOWS_HARDENING.md).

Microsoft splits the rules into two classes ([reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)):

- **Standard protection rules** — safe to set straight to **Block**: LSASS credential stealing (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`), vulnerable signed drivers (`56a863a9-875e-4185-98a7-b882c64b5ce5`), WMI event subscription persistence (`e6db77e5-3df2-4cf1-b95a-636979351e5b`).
- **All other rules** — run in **Audit** for 2–4 weeks first.

**Via GPO:** `Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction` > **Configure Attack Surface Reduction rules** > Enabled > **Show...**, then add each GUID as the value name with a mode as the value: `1` = Block, `2` = Audit, `6` = Warn, `0` = Off.

**Via Intune:** **Endpoint security** > **Attack surface reduction** > **Create policy** > platform **Windows**, profile **Attack Surface Reduction Rules** — each rule is a named dropdown, no GUIDs needed.

**Via PowerShell (pilot machines / labs):**

```powershell
# Standard protection rules straight to Block
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,56a863a9-875e-4185-98a7-b882c64b5ce5,e6db77e5-3df2-4cf1-b95a-636979351e5b `
  -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled

# Example: remaining rules to Audit (add the rest of the GUIDs from the rule table)
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a,5beb7efe-fd9a-4556-801d-275e5ffc04cc `
  -AttackSurfaceReductionRules_Actions AuditMode,AuditMode

# Verify
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
```

**Checkpoint:** Rule matches appear in Event Viewer under `Microsoft-Windows-Windows Defender/Operational` — event **1121** (block) and **1122** (audit) — and, if you run Defender for Endpoint, in the portal's ASR rules report.

**Watch out:** ASR settings from Intune or Configuration Manager overwrite conflicting `Set-MpPreference` values at startup — PowerShell is for pilots, not production distribution.

**Watch out:** The PSExec/WMI rule (`d1e49aac-8f56-4280-b9ba-993a6d77406c`) breaks Configuration Manager clients, which rely heavily on WMI. Leave it in Audit until you've confirmed your management tooling survives.

## Step 5 — Turn on Sysmon and command-line auditing

Hardening without telemetry is unverifiable. Two additions give you most of the visibility:

**Process creation auditing with command line (Event 4688):**

1. `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Detailed Tracking` > **Audit Process Creation** = Success.
2. `Computer Configuration > Administrative Templates > System > Audit Process Creation` > **Include command line in process creation events** = Enabled.
3. In the same baseline GPO, confirm the Security Option **Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings** is Enabled, so legacy category settings can't clobber your subcategories. Verify with `auditpol /get /subcategory:"Process Creation"`.

**Sysmon** ([official docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)) adds hashes, parent lineage, network connections, and tamper-resistant detail on top of 4688. Deploy it with a curated config — never bare:

```powershell
# Get Sysmon (Sysinternals) and a community baseline config
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

# Install with config; update later with: sysmon64 -c <newconfig.xml>
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify events are flowing
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Start from [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (broad, low-noise) or [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) (per-technique modules with ATT&CK mappings). The Sysmon event ID table and high-value filters (EID 1, 3, 8, 10, 22) are in [WINDOWS_HARDENING_REFERENCE.md](/WINDOWS_HARDENING_REFERENCE.md).

**Checkpoint:** A pilot machine shows Sysmon Event ID 1 with full command lines and hashes, Security log 4688 includes the *Process Command Line* field, and both are being collected by your SIEM or Windows Event Forwarding.

**Watch out:** Command lines land in the Security log **in plain text** — scripts that pass secrets as arguments will expose them to anyone who can read that log. Fix the scripts, restrict log read access, and raise the Security log size (the 20 MB default overwrites itself in minutes at this volume).

## Step 6 — Deploy Windows LAPS

Identical local admin passwords are a lateral-movement freeway (T1078.003 / pass-the-hash). Windows LAPS is built into Windows 11 and Server 2019+ (via 2023-04 updates and later) — no agent MSI. Official walkthrough: [Get started with Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

```powershell
# One-time, as Schema Admin: extend the AD schema
Update-LapsADSchema

# Let machines in the OU update their own password attribute
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=com"

# Grant your support group read access
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=corp,DC=com" -AllowedPrincipals "CORP\LAPS-Readers"
```

Then configure policy at `Computer Configuration > Administrative Templates > System > LAPS`: **Configure password backup directory** = Active Directory (this is the one mandatory setting), password length ≥ 20, age ≤ 30 days, **Enable password encryption** = Enabled (needs 2016 domain functional level). Retrieve and rotate:

```powershell
Get-LapsADPassword -Identity "WS-PILOT-01" -AsPlainText   # read
Invoke-LapsPolicyProcessing                                # apply policy now (on the client)
Reset-LapsPassword                                         # force immediate rotation (on the client)
```

**Checkpoint:** Event ID **10018** (`Microsoft-Windows-LAPS/Operational`) on pilot machines confirms passwords are backing up, and `Get-LapsADPassword` returns a random password only your authorized group can read.

**Watch out:** LAPS manages the password of an *existing* account — it never creates one. If you point it at a custom admin account name, create that account first, and disable or rename the built-in RID-500 Administrator per the baseline.

## Step 7 — Flip ASR from audit to enforce

After 2–4 weeks of audit data:

1. Pull every **1122** audit event (or Defender portal ASR report / advanced hunting `DeviceEvents | where ActionType endswith "Audited"`), then group hits by rule and by process.
2. For each hit, decide: fix the offending app or script, add a **per-rule exclusion** (GPO: **Apply a list of exclusions to specific attack surface reduction (ASR) rules**; Intune: the per-rule exclusion field), or accept the block. Prefer per-rule exclusions over global ones — a global exclusion blinds every rule at once.
3. Flip rules to Block in waves — noisy productivity-app rules last — by changing each GUID's value from `2` to `1` in the Step 4 policy.
4. Re-check event 1121 and your helpdesk queue for a week per wave before the next.

**Checkpoint:** All targeted ASR rules report mode 1 (Block) via `Get-MpPreference`, block events (1121) show only expected noise, and every exclusion is written down with a justification.

**Watch out:** Exclusions are the quiet way hardening rots. Each one is an accepted risk — record owner, reason, and review date in the Step 8 exception register, and re-review quarterly.

## Step 8 — Verify with a scanner and document exceptions

Prove the baseline stuck, machine-by-machine:

- **[CIS-CAT Lite](https://learn.cisecurity.org/cis-cat-lite)** (free, registration) scores a device 0–100 against supported CIS Benchmarks; **[CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro)** (CIS SecureSuite membership) covers 80+ benchmarks with remediation reporting.
- **Policy Analyzer** re-run from Step 2: compare effective state against the baseline `.PolicyRules` — the diff should now be empty except your documented exceptions.
- STIG shops: DISA's [SCC scanner and STIG Viewer](https://public.cyber.mil/stigs/) provide the same function against Windows STIGs.

Then write the exception register — one row per deviation: control ID, setting, deviation, business reason, compensating control, owner, review date. Store it with the GPO/Intune change records. Rescan on a schedule (monthly, or on every baseline version bump) and diff scores over time; feed results to your vulnerability-management process alongside patch compliance ([VULNERABILITY_MANAGEMENT_REFERENCE.md](/VULNERABILITY_MANAGEMENT_REFERENCE.md)).

**Checkpoint:** A dated scan report ≥ 90% conformant for the pilot, an exception register explaining the remainder, and a calendar entry for the next rescan. Now widen scope: pilot OU → department → fleet, repeating Steps 3–8 per ring.

**Watch out:** A 100% score on a scanner is not the goal — a *known* posture is. An undocumented 96% is worse than a documented 92%, because the undocumented gap is invisible risk nobody owns.

## What good looks like

- Every Windows device gets its configuration from a versioned baseline (GPO backup or Intune profile), not manual tweaks — and a fresh build lands compliant with no human intervention.
- The three standard-protection ASR rules are in Block everywhere; the rest are in Block with a short, justified per-rule exclusion list; event 1121/1122 volume is monitored, not ignored.
- Sysmon EID 1 and Security 4688 (with command line) flow to central collection, and a detection engineer can trace any process back to parent, hash, and command line.
- Every machine has a unique, rotating, escrowed local admin password; nobody knows a "standard" local admin password anymore.
- Scanner scores are stable or improving month over month, exceptions have owners and review dates, and a baseline version bump is a routine re-import — not a project.

## Go deeper

- [WINDOWS_HARDENING.md](/WINDOWS_HARDENING.md) — CIS control tables, ASR GUIDs, BitLocker, firewall, RDP/SMB hardening, and the 20-item quick checklist
- [WINDOWS_HARDENING_GPO.md](/WINDOWS_HARDENING_GPO.md) — GPO layering, dangerous-service disablement, tiered admin model, and misconfiguration-to-ATT&CK mapping
- [WINDOWS_HARDENING_REFERENCE.md](/WINDOWS_HARDENING_REFERENCE.md) — Sysmon deployment in depth, Windows Event Forwarding, PowerShell security (CLM, JEA), WDAC, and the full auditpol reference
- [ENTERPRISE_SECURITY_CONTROLS.md](/ENTERPRISE_SECURITY_CONTROLS.md) — where endpoint hardening sits in the wider enterprise control stack
- [DETECTION_RULES_REFERENCE.md](/DETECTION_RULES_REFERENCE.md) — Sigma rules that consume the 4688/Sysmon telemetry you just enabled
- [ATTACK_MITIGATIONS_REFERENCE.md](/ATTACK_MITIGATIONS_REFERENCE.md) — the ATT&CK mitigations (M1038, M1042, M1026...) these steps implement
- [Microsoft security baselines blog](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines) — baseline release announcements and change rationale
- [ASR rules deployment guide](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment) — Microsoft's full plan/test/enable/operationalize methodology
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — benchmark downloads, Build Kits, and profile definitions
- [Windows LAPS documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) — architecture, policy settings, and Entra ID scenarios

*Guides are procedures, not gospel — verify every command and console path against the current official documentation before you run it in production.*
