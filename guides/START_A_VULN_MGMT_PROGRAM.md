# Start a Vulnerability Management Program (First 90 Days)

> **By the end of this guide you will have a running vulnerability management program: a defensible asset inventory, an authenticated scanner producing real findings, a written KEV-first SLA policy, an SSVC-based prioritization queue, remediation tickets with named owners, and a one-page metrics pack for leadership.** This is for the security engineer or team lead who has been told "stand up vuln management" and has a Linux VM, a ticketing system, and 90 days — no prior program required.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| ~90 days elapsed; 2–4 hours to first scan | Intermediate | A Linux host with Docker, admin/root credentials for scan targets, a ticketing system, an executive sponsor | Asset inventory, authenticated scanner, KEV-first SLA policy, SSVC decision records, owner-routed tickets, leadership metrics pack |

## Before you start

- [ ] Read the signal-precedence model — KEV, then EPSS, then your context, then CVSS — in the [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md). The whole program hangs off that ordering.
- [ ] Skim the lifecycle phases, SLA targets, and KPI formulas in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) — this guide operationalizes them.
- [ ] Skim the 90-day starting plan in the [CTEM Reference](/CTEM_REFERENCE.md); this guide is the classic-VM subset of that loop, and where you graduate to next.
- [ ] A Linux host (4+ CPU, 8+ GB RAM) with [Docker Engine and the Compose plugin](https://docs.docker.com/engine/install/) installed.
- [ ] An executive sponsor and a first list of asset-owner contacts — mobilization dies without them (see the failure modes in the [CTEM Reference](/CTEM_REFERENCE.md)).
- [ ] Read access to your CMDB, cloud consoles, and identity provider, and write access to your ticketing system.

## Step 1 — Get an asset inventory you can defend

You cannot manage vulnerabilities on assets you don't know exist, and every scanner metric you report later is a percentage *of this inventory*.

1. Export whatever asset lists already exist: CMDB, cloud provider inventories, EDR console, DHCP leases, identity provider device lists.
2. Sweep your networks to find what those lists missed. Per the [official Nmap host discovery documentation](https://nmap.org/book/man-host-discovery.html), `-sn` performs host discovery without a port scan:

   ```bash
   nmap -sn 192.168.1.0/24
   ```

   Run one sweep per subnet, with network-team sign-off on timing.
3. Merge everything into one deduplicated inventory. Deduplicate by stable identity (MAC, cloud resource ID, serial), not by hostname — names collide and drift.
4. Give every row three fields: **named owner**, **criticality tier** (use the four-tier model in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), Tier 1 mission-critical through Tier 4 non-production), and **internet-facing yes/no**. The exposure flag becomes a prioritization input in Step 5.

**Checkpoint:** One inventory (spreadsheet or database), every row with owner + tier + exposure flag, plus a written list of the assets your sweep found that the CMDB didn't.

**Watch out:** The deltas *are* findings. Discovery pilots routinely surface large CMDB gaps — the [CTEM Reference](/CTEM_REFERENCE.md) cites a case where 30% of external assets were missing from the CMDB. Unknown assets and orphaned owners go on the remediation list like any CVE.

## Step 2 — Deploy a scanner and get first results

Greenbone Community Edition is free, unlimited-target, and officially distributed as Docker containers. Per the [official Greenbone Community Containers instructions](https://greenbone.github.io/docs/latest/22.4/container/index.html):

```bash
export DOWNLOAD_DIR=$HOME/greenbone-community-edition && mkdir -p $DOWNLOAD_DIR
curl -f -O -L https://greenbone.github.io/docs/latest/_static/compose.yaml --output-dir "$DOWNLOAD_DIR"
docker compose -f $DOWNLOAD_DIR/compose.yaml pull
docker compose -f $DOWNLOAD_DIR/compose.yaml up -d
```

A default user `admin` with password `admin` is created — change it immediately:

```bash
docker compose -f $DOWNLOAD_DIR/compose.yaml \
    exec -u gvmd gvmd gvmd --user=admin --new-password='<your-new-password>'
```

Browse to `https://127.0.0.1` (or `https://127.0.0.1:9392` — the official compose file publishes both) and sign in. Then run a first scan against a small test range, using the menu paths from the [Greenbone scanning manual](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html):

1. **Configuration > Targets** — create a target with a handful of hosts from Step 1.
2. **Scans > Tasks** — create a **New Task** pointing at that target, then click the start icon in the task row.

If your organization already owns Tenable, Qualys, or Rapid7, use it instead — the program design in the remaining steps is scanner-agnostic. For reference, Nessus installs per [Tenable's Linux install docs](https://docs.tenable.com/nessus/Content/InstallNessusLinux.htm) (`dpkg -i Nessus-<version>.deb`, `systemctl start nessusd`, UI at `https://localhost:8834`).

**Checkpoint:** A completed unauthenticated scan of a test range, with findings visible in the web UI.

**Watch out:** The vulnerability feeds load in the background after first start and take a while. A scan launched before the feed containers finish loading silently under-detects — confirm feed status is current in the web UI before trusting any results.

**Watch out:** The free Nessus Essentials license now covers only **5 IPs** ([Tenable's product page](https://www.tenable.com/products/nessus/nessus-essentials)) — fine for evaluating the product, not for scanning an estate. Older guides still say 16.

## Step 3 — Switch on authenticated coverage

Unauthenticated scans see only what the network exposes; they miss most local vulnerabilities and guess at versions. The [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) sets the KPI: **at least 80% of infrastructure scans authenticated.**

1. Create *dedicated* scan accounts — an SSH key-based account for Linux, a Windows account for SMB — with the least privilege your scanner's documentation requires. Never reuse a human's credentials; store the secrets in your vault.
2. In Greenbone, per the [scanning manual](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html): **Configuration > Credentials** — create SSH (username + key or password) and SMB credentials — then edit your targets to attach them. Windows targets need file and printer sharing enabled and the Remote Registry service running.
3. In Nessus, credentials live on the scan's **Credentials** page under the **Host** category (Windows logins, SSH, SNMPv3), per [Tenable's credentials documentation](https://docs.tenable.com/nessus/Content/Credentials.htm). Note Nessus uses the first credential that logs in successfully, so order matters.
4. Rescan the test range and compare: the authenticated run should return package-level CVEs (missing OS patches, local library versions) the first run never saw.

**Checkpoint:** Authenticated findings visible for both a Linux and a Windows target, and you can compute `authenticated scans / total scans` for your estate.

**Watch out:** Do not hand the scan account domain admin because "the scan needs to see everything." A scanner credential is a high-value target; scope it per the vendor's least-privilege guidance and alert on its use from anywhere that isn't the scanner.

## Step 4 — Write a KEV-first SLA policy

CISA's Known Exploited Vulnerabilities catalog is the highest-confidence public exploitation signal, and CISA strongly recommends all organizations require immediate handling of KEV-listed vulnerabilities in their vulnerability management plans ([CISA KEV program page](https://www.cisa.gov/known-exploited-vulnerabilities)).

1. Pull the live feed — never a snapshot; it changes multiple times weekly:

   ```bash
   curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev.json
   ```

   (CSV and a JSON schema are also published — links on the [KEV catalog page](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).)
2. Join it to your scan results on `cveID`. Every match is a confirmed-exploited vulnerability in *your* estate — that count is your **KEV exposure**, and its target is zero.
3. Write the SLA policy as a tier table: KEV-listed and internet-facing gets your fastest clock; KEV-listed internal next; high-probability non-KEV after that; everything else rides the patch cycle. Start from the worked example policy (P0–P4, with the fastest tier including "were we already hit?" forensic triage) in the [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) — it is labeled editorial there for a reason: the thresholds are policy choices, so make them deliberately and put a review date on them.
4. Benchmark your clocks against BOD 26-04, the federal directive whose timelines run from 3 days (publicly exposed + KEV + automatable + total control, with mandatory forensic triage) down to fix-on-upgrade. It binds US federal civilian agencies only, but it is the best-calibrated public benchmark available — details and the directive link are in the [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).
5. Define the exception path in the same document: request with compensating control and expiry date, security review against KEV status, CISO sign-off for Critical/High, auto-reopen at expiry — the workflow is spelled out in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

**Checkpoint:** A one-page SLA policy, signed by your sponsor, with tier triggers, day counts, the exception path, and a scheduled review date.

**Watch out:** "Not in KEV" never means "not exploited." KEV requires a CVE ID, reliable exploitation evidence, *and* a clear remediation action — actively exploited vulnerabilities without a fix are absent by design.

**Watch out:** The old BOD 22-01 flat "two weeks for everything" KEV regime was revoked in June 2026. Tooling defaults and vendor content still describe it — don't copy a dead policy into a new program.

## Step 5 — Prioritize with SSVC, not CVSS alone

A CVSS score is severity in the abstract; a program needs decisions — what do *we* do about *this one*, by *when*. SSVC replaces the score with a decision tree whose output is an action, and most of its inputs are now published for you per CVE.

1. Automate the derivable inputs. CISA Vulnrichment publishes three SSVC decision points — Exploitation, Automatable, Technical Impact — for every CVE it analyzes, and EPSS publishes a daily exploitation probability:

   ```bash
   # EPSS probability + percentile for one CVE
   curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"
   # Full daily EPSS snapshot (note -L; the URL redirects)
   curl -s -L -O https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
   ```

   Endpoints per [FIRST's EPSS data page](https://www.first.org/epss/data); record the model version alongside stored scores.
2. Supply the environmental inputs yourself — that is the half no feed can give you: **System Exposure** comes straight from the internet-facing flag in your Step 1 inventory; **Mission/Human Impact** comes from the criticality tier and your sponsor's business-impact judgment.
3. Walk your top findings through the [CISA SSVC calculator](https://www.cisa.gov/ssvc-calculator) — it steps through exploitation, automatability, technical impact, and mission & well-being, and exports the decision as PDF or JSON. **Save the export with the ticket.** That input vector is what makes "why didn't you patch the 9.8 first?" answerable a year later.
4. Produce a top-20 fix list, not a top-2000. The deep treatment — deployer decision model, pinned decision-point versions, precedence worked through cases — is in the [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).

**Checkpoint:** Every open Critical/High carries a decision outcome (defer / scheduled / out-of-cycle / immediate) and a recorded input vector — not just a score.

**Watch out:** Don't build an "EPSS × CVSS" composite score — FIRST itself says multiplying them does not compute probability × severity and calls the practice never a good idea. And don't let the environmental inputs default: an SSVC tree fed defaults is CVSS with extra steps.

## Step 6 — Route remediation to named owners

Security rarely owns the systems that need fixing. The handoff — not the fix — is where programs die, so the handoff is the deliverable.

1. Stand up a findings hub so every scanner import lands in one queue. Per the [official DefectDojo repository](https://github.com/DefectDojo/django-DefectDojo):

   ```bash
   git clone https://github.com/DefectDojo/django-DefectDojo
   cd django-DefectDojo
   docker compose up -d
   # after ~3 minutes of initialization:
   docker compose logs initializer | grep "Admin password:"
   ```

   Log in at `http://localhost:8080` and import your scan exports (Greenbone XML/CSV and Nessus files are supported import formats — see the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for the import workflow and API).
2. Route by exposure class, using the owner table in the [CTEM Reference](/CTEM_REFERENCE.md): OS/software CVEs to IT ops' patch pipeline, cloud misconfigurations to the platform team as IaC changes, identity findings to IAM, custom-code flaws to the product backlog.
3. Create the ticket **in the owner's system**, not yours, with the SLA due date from Step 4 and one sentence of business translation — "this lets an attacker read customer PII from the internet," not "CVE-2024-XXXX, CVSS 9.8."

**Checkpoint:** Every open Critical/High finding has a named owner, a route, and a due date derived from the SLA policy — and you can list the ones past due.

**Watch out:** "Ticket created" is not "risk reduced." Track closure and verify fixes (Step 8); a program measured on findings produced is a finding-generation program.

**Watch out:** Never dump a raw scanner export on an engineering team. Deduplicate, prioritize, translate — or the next export goes straight to their spam filter.

## Step 7 — Ship the first metrics pack

Leadership funds what it can see moving. Build the pack from the KPI formulas in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) and the reporting patterns in the [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md):

| Metric | Formula / source | Target |
|---|---|---|
| Scan coverage | assets scanned ÷ inventory (Step 1) | ≥ 95% |
| Authenticated scan rate | authenticated ÷ total scans | ≥ 80% |
| KEV exposure | open findings matching the KEV feed | 0 beyond emergency SLA |
| SLA compliance | remediated within SLA ÷ total, per tier | ≥ 95% Critical/High |
| MTTR | mean(close date − detection date), per severity | trending down |
| Exceptions past review | expired risk acceptances still open | 0 |

Report **four trended numbers** to leadership monthly — KEV exposure, Critical-tier MTTR vs. SLA, scan coverage, exceptions past review — each as a direction against last month, on one page.

**Checkpoint:** A one-page pack delivered to your sponsor, generated from queries you can rerun (the DefectDojo reporting API examples in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) automate it), not hand-assembled screenshots.

**Watch out:** Raw finding counts are vanity metrics — 40,000 findings discovered is an input, not an outcome. Report movement. And never trend EPSS scores across model-version boundaries; a version change is a methodology change, not a threat change.

## Step 8 — Verify fixes and start the second cycle

1. Close findings on **authenticated rescan evidence**, not on ticket status. The emergency out-of-band procedure in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) shows the full detect → patch → verify → close-out sequence for KEV-class events; the verification discipline applies to routine work too.
2. Track recurrence rate (reopened ÷ closed; target under 5%) — regressing fixes are a patch-pipeline problem, not a scanning problem.
3. Wire re-evaluation triggers: a new KEV entry, a large EPSS jump, or an exposure change invalidates a cached priority decision. Diff the KEV feed on every pull, not just new CVE IDs.
4. Put cycle 2 on the calendar before cycle 1 finishes. The second cycle is the program's real birthday — and its deltas (MTTR trend, recurrence, coverage growth) are your first honest report. When the loop runs on calendar without heroics, graduate it toward the full five-stage exposure loop — scoping, validation, choke points — in the [CTEM Reference](/CTEM_REFERENCE.md).

**Checkpoint:** At least one finding closed by rescan evidence, a recurrence number you can state, and a dated calendar entry for the next cycle.

## What good looks like

- Scan coverage ≥ 95% of a *written* inventory, with ≥ 80% of infrastructure scans authenticated — and you can name the assets you cannot scan.
- KEV exposure is zero beyond your emergency SLA, and the policy that says so is signed, dated, and has a review date.
- Every deferred Critical has a recorded SSVC input vector that survives an audit — "deferred because Exploitation=None, Exposure=Small, control validated on date X."
- Remediation tickets live in the owners' systems, and past-due items are a report, not a surprise.
- Leadership has seen the same four trended numbers at least twice, and the second cycle started without anyone pushing.

## Go deeper

**In this library:**

- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) — the full operational layer: scanner CLIs and APIs, DefectDojo workflow, patch management, compliance mappings.
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) — SSVC decision models, KEV semantics, BOD 26-04, EPSS interpretation, and the example SLA policy this guide builds on.
- [CTEM Reference](/CTEM_REFERENCE.md) — the five-stage exposure loop this program grows into, with the 90-day plan and documented failure modes.
- [CVE Reference](/CVE_REFERENCE.md) — CVSS v3.1/v4.0 mechanics, EPSS/KEV parsing code, CVE JSON record schema.
- [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) — formulas and executive-reporting patterns behind Step 7.
- [GRC Reference](/GRC_REFERENCE.md) — risk acceptance and governance context for the exception workflow.

**Authoritative external resources:**

- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — the live catalog, feeds, and schema.
- [CERT/CC SSVC documentation](https://certcc.github.io/SSVC/) — the decision models, versioned decision points, and machine-readable decision tables.
- [FIRST EPSS](https://www.first.org/epss/) — model documentation, FAQ, and daily data.
- [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final) — enterprise patch management planning: maintenance groups, risk responses, and the planned/emergency split.

*Guides are procedures: commands, menu paths, and license terms drift, so verify every step against the current official documentation before using it in production.*
