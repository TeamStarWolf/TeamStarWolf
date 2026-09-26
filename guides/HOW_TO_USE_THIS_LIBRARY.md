# How to Use This Library

> **In about 30 minutes you will know what lives where in this library, be able to find any technique, control, or reference in under a minute, and have a personal entry path picked out.** This guide is for anyone opening TeamStarWolf for the first time — a student, a working SOC analyst, or a security lead — no prior knowledge of the repo required.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 30–45 min | Beginner | A web browser; optionally Git, jq, and Python for Step 8 | A working mental map of the library and a bookmarked reading path for your role |

## Before you start

- [ ] A modern browser pointed at the [live site](https://teamstarwolf.github.io/TeamStarWolf/) — everything through Step 7 happens there
- [ ] The ATT&CK vocabulary basics — *tactic*, *technique*, *sub-technique*. Skim the [Glossary](/GLOSSARY.md) or MITRE's official [Get Started resources](https://attack.mitre.org/resources/)
- [ ] Optional, for Step 8 only: [Git](https://git-scm.com/docs/git-clone), [jq](https://jqlang.org/manual/), and [Python 3](https://www.python.org/downloads/) installed locally

## Step 1 — Open the library on the right surface

The library has two faces backed by the same files:

1. **The live site** — [teamstarwolf.github.io/TeamStarWolf](https://teamstarwolf.github.io/TeamStarWolf/). It opens on a navigation homepage ([HOME](/HOME.md)) with stat tiles, a Quick router, and full-text search. Use this for reading and finding things.
2. **The GitHub repo** — [github.com/TeamStarWolf/TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf). It opens on the [README](/README.md), which carries the "At a glance" numbers and the "Start here" table. Use this for raw files, datasets, issues, and pull requests.

Every page on the live site has an "Edit this page on GitHub" link at the top, so you can hop between surfaces from wherever you are.

**Checkpoint:** You can see the homepage hero ("An open, threat-informed cybersecurity reference library") and the stat tiles: 139 reference docs, 47 discipline paths, 28 Navigator layers.

**Watch out:** Dataset links (the `.jsonl` files) always open on GitHub, not on the site — the site's hash router cannot serve raw data files. That is by design, not a broken link.

## Step 2 — Learn what lives where

The repo is one flat root of reference documents plus a few purposeful folders:

| Location | What lives there |
|---|---|
| Root `*.md` files | The 139 reference documents — one deep, self-contained doc per domain (e.g. [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Cloud Security](/CLOUD_SECURITY_REFERENCE.md), [SIEM](/SIEM_REFERENCE.md)) |
| `disciplines/` | 47 guided learning paths that sequence those references in the right order — hub at [Discipline Paths](/disciplines/README.md) |
| `guides/` | Step-by-step how-to guides (you are reading one) — procedures, where the references are doctrine |
| `techniques/` | Per-technique ATT&CK detail pages, one file per tactic — hub at [Technique Detail Pages](/techniques/README.md) |
| `detections/` | Detection engineering: 691 MITRE detection strategies + 1,739 analytics ([Detection Strategies](/detections/strategies/README.md)) and 65 multi-platform queries ([Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md)) |
| `data/` | Machine-readable JSONL datasets — every mapping in the library as one JSON object per line (ATT&CK, D3FEND, CWE, CAPEC, ATLAS, Engage, F3, and the NIST 800-53 coverage edges) |
| `navigator/` | 28 ATT&CK Navigator heatmap layers — index at [Navigator Layers](/navigator/index.md) |
| `scores/` | Gap analyses computed from the datasets — start with [Priority Gap Analysis](/scores/attack_priority_gaps.md) |
| `research/` | Curated research indexes — conference talks, tool crosswalks, lab tracks |

One companion lives outside this repo: [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/), an interactive ATT&CK workbench that consumes the same coverage data published here.

**Checkpoint:** Given any question — "how does Kerberoasting detection work", "which controls map to T1078", "where do I start learning cloud security" — you can name the folder it will be answered in before you search.

## Step 3 — Find anything three ways

1. **Search.** On the live site, press `/` (or click the search box) and type a term or an ATT&CK technique ID — `T1059` works, and so does `Kerberoasting`. Sub-techniques use dot notation: `T1059.001`. Press `Esc` to clear.
2. **The Reference Index.** [INDEX](/INDEX.md) is the complete alphabetical listing of all 139 documents with one-line descriptions — the fastest way to scan what exists.
3. **The sidebar and Quick router.** The sidebar groups every doc by domain (Coverage & Data, Defense & Detection, Offensive Security, GRC, and so on). The homepage Quick router does the same by *goal*: "Build detections", "Respond now", "Harden", "Map coverage & gaps".

**Checkpoint:** Searching `T1059` returns hits across the Technique Atlas, detection strategies, and threat group profiles — the same technique seen from several angles.

**Watch out:** Site search indexes pages reachable from the sidebar and caches the index for an hour, so the very first search after a page load can take a moment to warm up.

## Step 4 — Trace the threat-informed data model

Everything in the library hangs off one knowledge graph, defined in the [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md):

```
CVE  →  CWE  →  CAPEC  →  ATT&CK  →  D3FEND
(exposure) (weakness) (attack pattern) (behavior) (defense)
                             │
                             └─→  NIST 800-53 controls (via CTID)
```

Read it forward to go from a vulnerability to the defensive action that stops it; read it backward to go from an observed behavior to the root-cause weaknesses in your environment. Each hop has a home:

- **Behavior** — [ATT&CK Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md) scores all 691 Enterprise techniques; [Technique Detail Pages](/techniques/README.md) give the full per-technique write-up
- **Weakness and pattern** — [CWE Reference](/CWE_REFERENCE.md) (969 weaknesses) and [CAPEC Reference](/CAPEC_REFERENCE.md) (615 patterns, 177 bridging to ATT&CK)
- **Defense** — [D3FEND Reference](/D3FEND_REFERENCE.md) (156 countermeasures) and the 5,314 NIST 800-53 control→technique edges in [Controls Mapping](/CONTROLS_MAPPING.md), sourced from the [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/)
- **The on-disk shape** — [Coverage Schema](/COVERAGE_SCHEMA.md) documents the vendor → control → technique edge tables that power the Navigator layers and gap scores

**Checkpoint:** You can answer "which NIST 800-53 controls mitigate Valid Accounts (T1078)?" using [Controls Mapping](/CONTROLS_MAPPING.md), and you know the same fact exists as machine-readable rows in `data/control_to_technique.jsonl`.

## Step 5 — Enter as a student or career changer

1. Open the [Discipline Paths hub](/disciplines/README.md) and pick one path from the cluster that matches your goal — for example [Security Operations](/disciplines/security-operations.md) or [Detection Engineering](/disciplines/detection-engineering.md). Each path sequences the references in learning order; resist reading the library alphabetically.
2. Keep the [Glossary](/GLOSSARY.md) open in a second tab for unfamiliar terms.
3. Pair the reading with practice: [Hands-On Labs](/LABS.md) maps free lab platforms to each domain, and [Home Lab Setup](/HOMELAB_SETUP.md) shows how to build your own.
4. When you want direction, [Career Paths](/CAREER_PATHS.md) and [Certifications](/CERTIFICATIONS.md) map roles to skills and certs.

**Checkpoint:** One discipline path bookmarked, its first two references skimmed, and a lab platform account created.

## Step 6 — Enter as a SOC analyst

Worked example — an alert fires on suspicious PowerShell:

1. Press `/` and search the technique ID from the alert (or the behavior name): `T1059`.
2. Open its entry in the [Technique Detail Pages](/techniques/README.md) — description, mitigations, NIST controls, detections, and the groups and software that use it, on one page.
3. Follow the detection angle: [Detection Strategies](/detections/strategies/README.md) gives MITRE's per-technique detection logic and log sources, and the [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) has ready-to-adapt queries for Splunk, Elastic, Microsoft, Chronicle, and CrowdStrike.
4. Check you actually collect the telemetry the detection needs in [Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md).
5. For scoping and attribution context, look the technique up in [Threat Group Profiles](/THREAT_GROUP_PROFILES.md); if an incident is unfolding, pivot to [IR Playbooks](/IR_PLAYBOOKS.md).

**Checkpoint:** From one technique ID you reached its detection logic, the queries for your SIEM, the log sources they require, and the adversaries known to use it — without leaving the library.

**Watch out:** The queries are reference logic, not drop-in rules. Field names, index names, and thresholds vary by environment — tune and test in a lab before deploying, per your platform's official documentation.

## Step 7 — Enter as a security lead

Worked example — "where are our coverage gaps?":

1. Read the [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md) for the model, then [ATT&CK Matrix Analysis](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md) for the 24 analytic lenses you can apply to a matrix.
2. Open the [Navigator Layers index](/navigator/index.md) and click any layer's "↗ Navigator" link — it opens MITRE's hosted [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) with the layer pre-loaded via its documented `layerURL` fragment. Start with the master NIST 800-53 coverage layer.
3. Read the ranked write-ups: [Priority Gap Analysis](/scores/attack_priority_gaps.md) lists the most-used, least-covered techniques, and the Framework Blind Spots layer shows the 223 techniques with no mapped NIST 800-53 control.
4. For vendor questions — "what does our EDR actually cover?" — use the vendor layers and the edge tables described in [Coverage Schema](/COVERAGE_SCHEMA.md).
5. For richer interactive analysis (EPSS, CISA KEV, detection-content correlation), move to the [ATTACK-Navi workbench](https://teamstarwolf.github.io/ATTACK-Navi/).

**Checkpoint:** A coverage heatmap open in ATT&CK Navigator and a shortlist of high-priority gap techniques for your program.

**Watch out:** Layers are pinned to ATT&CK versions (the CTID control mappings are built on ATT&CK v16.1; the analytic layers on v18.1). Comparing layers across versions can silently drop or mismatch techniques — check the version badge Navigator shows for each layer. Also, "no mapped control" means no *NIST 800-53 mapping exists*, not that a technique is impossible to defend — treat blind spots as prompts for detection engineering, not verdicts.

## Step 8 — Take the data home

Every mapping is machine-readable, so you can query it instead of reading it.

1. Clone the repo (syntax per the [official git-clone docs](https://git-scm.com/docs/git-clone)):

   ```bash
   git clone https://github.com/TeamStarWolf/TeamStarWolf.git
   cd TeamStarWolf
   ```

2. Ask questions with [jq](https://jqlang.org/manual/) — `select()` filters rows, `startswith()` matches ID prefixes, `-c` prints one object per line:

   ```bash
   # Which tracked threat groups use Command and Scripting Interpreter (T1059, any sub-technique)?
   jq -c 'select(.technique_id | startswith("T1059"))' data/attack/group_to_technique.jsonl

   # Which NIST 800-53 controls mitigate Valid Accounts (T1078)?
   jq -c 'select(.attack_technique == "T1078")' data/control_to_technique.jsonl
   ```

3. If you edit or regenerate any edge table, validate before committing — CI runs the same check:

   ```bash
   python scripts/validate_jsonl.py
   ```

   The canonical field names it enforces are documented in [Coverage Schema](/COVERAGE_SCHEMA.md).

**Checkpoint:** The T1078 query returns 25 control edges, each carrying the control ID, its description, confidence, and the CTID source URL.

**Watch out:** A few reference docs quote attack-tool and detection strings that some antivirus engines flag on checkout — a false positive on plain markdown. If a file vanishes after cloning, check your AV quarantine before assuming the repo is broken.

## What good looks like

- You can name the folder that answers a question before you search for it.
- Any ATT&CK technique ID takes you under a minute to resolve into mitigations, controls, detections, and known adversaries.
- You entered through the path that matches your role and have a bookmarked reading sequence, not a vague plan to "read the library".
- You understand the CVE → CWE → CAPEC → ATT&CK → D3FEND chain well enough to explain why a coverage heatmap and a JSONL edge table are the same facts in two forms.
- Gaps you cite come from the scored analyses and Navigator layers, not from impressions.

## Go deeper

**In the library:**

- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md) — the doctrinal core: the knowledge graph, the data-source stack, and the per-technique coverage-stack model
- [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md) — 24 ways to read an ATT&CK matrix before you make decisions with one
- [Reference Index](/INDEX.md) — the complete document catalog
- [Discipline Paths hub](/disciplines/README.md) — all 47 learning paths
- [Coverage Schema](/COVERAGE_SCHEMA.md) — the data model behind the layers and gap scores
- [Frameworks](/FRAMEWORKS.md) — how NIST CSF, 800-53, CIS, and ISO relate to the MITRE stack

**Official external resources:**

- [MITRE ATT&CK — Get Started](https://attack.mitre.org/resources/) — ATT&CK 101 and the four primary use-case guides
- [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) — the layer format and `layerURL` loading, from the source
- [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) — the authoritative NIST 800-53 → ATT&CK mappings this library ships
- [jq manual](https://jqlang.org/manual/) — the full filter language for querying the datasets

*Guides are procedures: verify every command against current official documentation before production use.*
