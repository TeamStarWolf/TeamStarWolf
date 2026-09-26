# Assess Your M365 Tenant with ScubaGear

> **By the end of this guide you will have scored your Microsoft 365 tenant against CISA's SCuBA secure configuration baselines, read the conformance report like an assessor, and turned the failures into a prioritized remediation plan that won't lock anyone out.** Written for M365 administrators and security engineers who can get read-level admin access to a tenant — no prior ScubaGear experience assumed.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 2–4 hours for the first full run and report review | Intermediate | Windows + PowerShell 5.1, a Global Reader account (or product-admin equivalents) | HTML/JSON/CSV conformance reports, an `ActionPlan.csv` of failing mandatory controls, and a scheduled re-run cadence |

ScubaGear is CISA's free assessment tool for Microsoft 365. It queries your tenant's settings through Microsoft's APIs, evaluates them against the [SCuBA Secure Configuration Baselines](https://github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines) using Open Policy Agent, and emits a scored report. It reads configuration; it changes nothing. Under [BOD 25-01](https://www.cisa.gov/news-events/directives/bod-25-01-implementing-secure-practices-cloud-services) these baselines are mandatory for U.S. federal civilian agencies — for everyone else they are the best free answer to "is my tenant configured sanely?" The doctrinal context — why tenant misconfiguration is the dominant SaaS exposure class — lives in this library's [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md).

## Before you start

- [ ] **A Windows machine with PowerShell 5.1.** ScubaGear requires PowerShell 5, which only ships on Windows ([dependencies doc](https://cisagov.github.io/ScubaGear/docs/prerequisites/dependencies.html)).
- [ ] **An account with the Global Reader role** — or the per-product admin roles listed in Step 3 ([interactive permissions doc](https://cisagov.github.io/ScubaGear/docs/prerequisites/interactive.html)).
- [ ] **A tenant admin available for one-time consent.** The first run requests seven delegated Microsoft Graph permissions that require admin consent (Step 3).
- [ ] **Know which cloud your tenant lives in**: `commercial`, `gcc`, `gcchigh`, or `dod` ([parameters doc](https://cisagov.github.io/ScubaGear/docs/configuration/parameters.html)).
- [ ] **Skim the SCuBA and M365-hardening sections** of the [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md) so the baseline's control choices make sense before the report scores you on them.
- [ ] **For unattended re-runs only**: rights to create an Entra ID app registration and a certificate ([non-interactive permissions doc](https://cisagov.github.io/ScubaGear/docs/prerequisites/noninteractive.html)).

## Step 1 — Understand what ScubaGear measures

Read before you run. ScubaGear scores seven M365 products, each against its own baseline document:

| Product name (flag value) | Baseline covers |
|---|---|
| `aad` | Microsoft Entra ID — MFA, conditional access, consent settings, privileged roles |
| `securitysuite` | Defender for Office 365 + Microsoft Purview functions (supersedes the older `defender` baseline; the repo is mid-reorganization, so check the [baselines directory](https://github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines) before quoting policy IDs) |
| `exo` | Exchange Online — transport rules, external forwarding, DMARC/SPF/DKIM |
| `powerbi` | Power BI sharing and workspace settings |
| `powerplatform` | Power Platform environment and connector governance |
| `sharepoint` | SharePoint Online & OneDrive — external sharing defaults, link scopes |
| `teams` | Teams — external access, meeting policies, app management |

Every policy has an ID (for example `MS.AAD.3.1v1`) and a criticality: **SHALL** policies are mandatory, **SHOULD** policies are recommended. BOD 25-01 made the SHALLs enforceable for federal agencies with documented deviations — that "mandatory floor plus documented exceptions" pattern is worth copying even if no directive applies to you.

**Checkpoint:** You can name which of the seven products your tenant actually uses — that list is what you'll assess in Step 4.

## Step 2 — Install ScubaGear and its dependencies

In a PowerShell 5.1 session:

```powershell
Install-Module -Name ScubaGear
Install-ScubaDependencies
Invoke-SCuBA -Version
```

`Install-ScubaDependencies` pulls the two required PowerShell modules (`Microsoft.Graph.Authentication` and `powershell-yaml`) and downloads the Open Policy Agent executable to `C:\Users\<you>\.scubagear\Tools`. The older `Initialize-SCuBA` command still works as a backward-compatible alias.

**Checkpoint:** `Invoke-SCuBA -Version` prints a version number without errors.

**Watch out:** On proxied corporate networks the OPA download is the piece that fails. If it does, run `Install-OPAforSCuBA` separately or place the tested OPA version manually per the [dependencies doc](https://cisagov.github.io/ScubaGear/docs/prerequisites/dependencies.html) — ScubaGear will not evaluate anything without it.

## Step 3 — Set up least-privilege access

Do not run this as Global Administrator just because it works. ScubaGear only reads, so give it read-level roles.

**Interactive runs (your first run):** Global Reader covers Entra ID, Security Suite, Exchange Online, SharePoint, and Teams. Two products need more because their APIs demand it: Power BI requires **Fabric Administrator** with a Power BI/Fabric license, and Power Platform requires **Power Platform Administrator** with a "Power Apps for Office 365" license ([interactive permissions doc](https://cisagov.github.io/ScubaGear/docs/prerequisites/interactive.html)). On first sign-in, ScubaGear requests seven delegated Graph permissions — `Directory.Read.All`, `Policy.Read.All`, `PrivilegedAccess.Read.AzureADGroup`, `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `RoleManagement.Read.Directory`, `RoleManagementPolicy.Read.AzureADGroup`, `User.Read.All` — which need one-time admin consent.

**Unattended runs (for the Step 9 schedule):** create an Entra app registration with certificate authentication per the [non-interactive permissions doc](https://cisagov.github.io/ScubaGear/docs/prerequisites/noninteractive.html):

1. Register an application in Entra ID and grant it the **application** (not delegated) versions of the seven Graph permissions above.
2. Add `Exchange.ManageAsApp` from the Office 365 Exchange Online API (needed for `exo` and `securitysuite`).
3. Add `Sites.FullControl.All` from the SharePoint API (needed for `sharepoint`).
4. Assign the service principal the **Global Reader** directory role (needed for Security Suite and Teams checks).
5. Create or import a certificate into `Cert:\CurrentUser\My` on the machine that will run the assessments — ScubaGear requires that specific store — and upload its public key to the app registration. Record the thumbprint.

**Checkpoint:** Either a Global Reader account you can sign in with, or an app registration with admin-consented permissions and a certificate thumbprint recorded somewhere safe.

**Watch out:** `Sites.FullControl.All` and `Exchange.ManageAsApp` make this service principal a high-value target even though ScubaGear only reads. Treat the certificate's private key like an admin credential, and put the app registration itself on the OAuth-app review cycle described in the [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md) — an assessment tool that becomes an unowned legacy app is exactly the failure mode it exists to find.

## Step 4 — Run your first assessment

Start with one product to shake out authentication, then go wide:

```powershell
# Smoke test: Entra ID only
Invoke-SCuBA -ProductNames aad -M365Environment commercial

# The default run covers everything except Power Platform and Power BI
Invoke-SCuBA

# Everything, including Power Platform and Power BI
Invoke-SCuBA -ProductNames *
```

Set `-M365Environment` to `gcc`, `gcchigh`, or `dod` if that's where your tenant lives. Expect a sign-in prompt (or several — different products use different APIs). Use `-OutPath` to control where reports land and add `-DisconnectOnExit` on shared machines to delete the cached authentication tokens afterward.

For an unattended run with the Step 3 app registration:

```powershell
Invoke-SCuBA -ProductNames * `
  -CertificateThumbprint <thumbprint> `
  -AppID <application-client-id> `
  -Organization yourtenant.onmicrosoft.com
```

**Checkpoint:** A timestamped output folder exists and `BaselineReports.html` has opened in your browser with a scored summary per product.

**Watch out:** Running against a GCC/GCC-High/DoD tenant without the matching `-M365Environment` value fails with confusing authentication and endpoint errors — set it explicitly rather than debugging the wrong problem.

## Step 5 — Read the report like an assessor

The output folder contains layers for different audiences ([reports doc](https://cisagov.github.io/ScubaGear/docs/execution/reports.html)):

- **`BaselineReports.html`** — the summary dashboard; one row per product with pass/fail counts.
- **`IndividualReports/`** — a detailed HTML report per product: every policy ID, its requirement text, its criticality, the result, and a details column.
- **`ScubaResults_<UUID>.json`** — the full machine-readable output (metadata, summary counts, results, raw provider data) for your SIEM or scripts.
- **`ScubaResults.csv`** — results only, in flat parseable form.
- **`ActionPlan.csv`** — pre-filtered to **failing SHALL controls**, with empty columns for the failure reason and remediation timeline. This file is your working artifact for Steps 6–7.

Read the details column, not just the color: some baseline policies cannot be checked via API and require manual verification, so a report that's green everywhere the API can see is not the same as a conformant tenant.

**Checkpoint:** You can state your SHALL-failure count per product, and `ActionPlan.csv` lists each one.

## Step 6 — Prioritize failures against the baselines

All failures are not equal. Order the work:

1. **SHALL failures first** — they are the baseline's mandatory floor and they populate `ActionPlan.csv` for a reason.
2. **Within the SHALLs, lead with the controls that have incident pedigree.** The [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md) case studies map directly onto baseline policies: MFA gaps and legacy authentication (Midnight Blizzard's entry point was an MFA-less account), unrestricted user consent and unaudited app permissions (its escalation path), and permissive sharing defaults in SharePoint/OneDrive.
3. **Then SHOULDs**, ordered by the same logic.

Assign every failure an owner and a target date in `ActionPlan.csv`, and feed the list into the same remediation pipeline you use for vulnerabilities — findings with owners and SLAs, not a report on a shelf ([CTEM Reference](/CTEM_REFERENCE.md), mobilization stage).

**Checkpoint:** A ranked `ActionPlan.csv` where every failing SHALL has an owner and a date.

**Watch out:** Don't burn the first week arguing about SHOULDs while SHALL failures sit open. The SHALL/SHOULD split exists precisely so the triage argument is already settled.

## Step 7 — Remediate without locking anyone out

The highest-impact fixes — conditional access, MFA enforcement, legacy-auth blocking, consent restriction — are also the ones that can lock out your CEO on a Monday. Sequence them:

- **Use report-only mode for conditional access changes first.** Watch the sign-in logs for who *would* have been blocked before you enforce.
- **Exclude and protect break-glass accounts** before tightening authentication policy, and alert on their use — vaulted emergency access is part of the identity baseline, not an exception to it ([Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)).
- **Inventory before you block legacy authentication.** Check sign-in logs for legacy-protocol usage; old clients, scanners, and service mailboxes still using it will break silently.
- **Pair consent restriction with the admin consent workflow.** If you disable user consent without giving users a request path, you get shadow-IT workarounds instead of security.
- **Change one control class per change window**, then verify with a targeted re-run: `Invoke-SCuBA -ProductNames exo` re-scores just the product you touched in minutes.

**Checkpoint:** Each remediation has a rollback plan, and a targeted re-run flips the control from fail to pass.

**Watch out:** A fix that "passes" by disabling a business capability nobody signed off on is a future emergency change. Every remediation in `ActionPlan.csv` should name the business owner who accepted the change, not just the engineer who made it.

## Step 8 — Record deviations in a config file

Some baseline policies genuinely won't apply to you. Don't let them rot as permanent red rows — document them in a ScubaGear YAML configuration file ([configuration doc](https://cisagov.github.io/ScubaGear/docs/configuration/configuration.html)), which also makes every future run repeatable:

```yaml
ProductNames: ['aad', 'securitysuite', 'exo', 'sharepoint', 'teams']
M365Environment: commercial
OmitPolicy:
  MS.EXO.4.3v1:
    Rationale: "Policy applies to federal executive branch agencies only"
    Expiration: 2027-03-31
AnnotatePolicy:
  MS.AAD.2.1v1:
    Comment: "Remediation in progress; CA policy in report-only mode"
    RemediationDate: 2026-11-30
```

Run with `Invoke-SCuBA -ConfigFilePath .\scuba-config.yaml`. Omitted policies render as gray "Omitted" rows with your rationale; annotations append to the details column of failing controls. Keep the config in version control — it is your deviation register, which is exactly what BOD 25-01 requires agencies to maintain ([GRC & Compliance Reference](/GRC_COMPLIANCE_REFERENCE.md)).

**Checkpoint:** A committed config file; a re-run shows your omissions in gray with rationale text and your annotations on failing rows.

**Watch out:** An omission without an `Expiration` date is a permanent exception nobody will ever revisit. Set one, always — expiry is what turns an exception into a review.

## Step 9 — Schedule re-runs and track drift

One assessment is a snapshot; configuration drifts back. Make it a cadence:

- **Monthly or better**, using the Step 3 app registration and the Step 8 config file so runs are hands-off and identical.
- **Archive `ScubaResults_<UUID>.json` from every run** and trend the SHALL-failure count per product over time — that number is a reportable posture metric ([Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md)), and a regression (a control flipping from pass back to fail) is a drift signal worth alerting on in your SIEM ([SIEM Reference](/SIEM_REFERENCE.md)).
- **Keep the tool and baselines current**: run `Update-ScubaGear` before scheduled runs pick up a stale version, and re-check the baselines directory when policy IDs change — the Defender/Security Suite reorganization is a live example.

**Checkpoint:** A second run's results archived next to the first, with the failure-count delta visible — you are now measuring drift, not just posture.

## What good looks like

- Every failing SHALL control has an owner and a date in `ActionPlan.csv` — or a documented omission with rationale and expiry in the config file. Nothing is silently ignored.
- Assessments run unattended on a monthly-or-better cadence under a least-privilege service principal, not an admin's personal account.
- Results are archived per run and the SHALL-failure trend is reported as a metric; regressions raise alerts.
- Remediations shipped through report-only and pilot phases; the sign-in logs show no lockout spike, and break-glass accounts remain excluded, vaulted, and alarmed.
- The ScubaGear service principal itself appears in your OAuth-app inventory with an owner and a review date.

## Go deeper

**In this library:**

- [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md) — the doctrinal base: SCuBA, BOD 25-01, the case studies behind the controls, and the full M365 hardening checklist
- [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) — conditional access, MFA tiers, and break-glass account handling behind the Step 7 sequencing
- [CTEM Reference](/CTEM_REFERENCE.md) — running baseline failures through a scoped exposure-management loop with owners and SLAs
- [SIEM Reference](/SIEM_REFERENCE.md) — exporting M365 audit logs and building the drift and consent-grant detections this assessment motivates
- [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) — turning the SHALL-failure trend into a defensible program metric
- [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) — where tenant posture fits in the broader cloud shared-responsibility picture

**External:**

- [ScubaGear documentation site](https://cisagov.github.io/ScubaGear/) — the authoritative install, permissions, execution, and configuration reference
- [ScubaGear repository and baselines](https://github.com/cisagov/ScubaGear) — source, releases, and the current baseline documents with per-policy IDs
- [CISA SCuBA project page](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project) — the program behind the tool, including Google Workspace's ScubaGoggles counterpart
- [BOD 25-01](https://www.cisa.gov/news-events/directives/bod-25-01-implementing-secure-practices-cloud-services) — the directive that made these baselines mandatory for federal agencies, and a useful program template for everyone else

*Guides are procedures, and tools move faster than documents: verify every command and permission name against the current official ScubaGear documentation before production use.*
