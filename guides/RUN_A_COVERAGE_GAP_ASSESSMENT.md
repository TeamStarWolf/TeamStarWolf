# Run an ATT&CK Coverage Gap Assessment

> **By the end of this guide you will have a ranked, owner-assigned list of the ATT&CK techniques your adversaries use most and your controls cover least — backed by a Navigator layer you can re-run every quarter.** It is written for a security engineer or analyst who knows what ATT&CK is but has never turned it into a prioritized work queue.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 2–4 hours (first run) | Intermediate | A browser, this library's Navigator layers and score reports; optionally Git + Node.js for ATTACK-Navi | A priority-gap Navigator layer (JSON) and a ranked gap register with owners |

## Before you start

- [ ] Read the lens model in the [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md) — this guide operationalizes its five lens families and its eight-pass analysis workflow.
- [ ] Skim the [Threat Group Profiles](/THREAT_GROUP_PROFILES.md) — the 168 tracked ATT&CK groups you will scope from.
- [ ] Skim the two precomputed reports you will reconcile against: the [ATT&CK Priority Gap Analysis](/scores/attack_priority_gaps.md) and the [vendor-stack Coverage Gap Analysis](/scores/coverage_gaps.md).
- [ ] Know where the layers live: the [Navigator layer index](/navigator/index.md) lists every hosted heatmap with one-click load links.
- [ ] Confirm you can open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) in a browser; keep the official [Navigator usage doc](https://github.com/mitre-attack/attack-navigator/blob/master/USAGE.md) handy.
- [ ] Optional but recommended: Git and a current Node.js LTS release to run [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) locally in Step 6.

## Step 1 — Scope your threat model

Coverage against "all of ATT&CK" is noise. Coverage against *your* adversaries is a plan.

1. Open the [Threat Group Profiles](/THREAT_GROUP_PROFILES.md) table (sorted by technique breadth) and shortlist **3–6 groups** that target your sector, geography, or tech stack. Write down each group's `G` ID (for example `G1015 Scattered Spider` for identity-centric eCrime, `G1017 Volt Typhoon` for critical-infrastructure living-off-the-land).
2. For each shortlisted group, confirm the pick on its official page at [attack.mitre.org/groups](https://attack.mitre.org/groups/) — check the "Associated Groups" aliases against names in your threat intel reporting so you don't select the same actor twice under two names.
3. Note your in-scope platforms (Windows, Linux, macOS, cloud, SaaS, network). You will filter the matrix to these later.
4. Write one sentence per group stating *why* it is in scope. This becomes the assessment's audit trail.

**Checkpoint:** A short document with 3–6 group IDs, one selection rationale each, and a platform list.

**Watch out:** Don't scope by fame. A group with 100+ techniques that targets a different sector produces a worse work queue than a 40-technique group that actually hunts companies like yours. The profiles table's *Techniques* column measures ATT&CK's visibility into the group, not the threat to you.

## Step 2 — Build one Navigator layer per threat group

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Click **Create New Layer** and choose **Enterprise** (use **More Options** only if you deliberately need an older ATT&CK version).
2. Open the **search & multiselect** interface (magnifying-glass icon in the selection controls). Expand the **Threat Groups** section, find your first group, and click **select**. Per the official usage doc, this selects every technique mapped to (used by) that group.
3. With the techniques selected, open **scoring** in the technique controls and assign a score of `1`.
4. Rename the layer to the group ID via the **layer information** control (for example `G1015-scattered-spider`), then deselect everything.
5. Repeat in a fresh layer (new tab) for each shortlisted group — one layer per group, every scored cell worth `1`.

**Checkpoint:** One Navigator tab per group, each named for its `G` ID, each with that group's techniques scored `1`.

**Watch out:** Check the multiselect options for **Select techniques across tactics** and **Select sub-techniques with parent** before scoring — with cross-tactic selection off, a technique that appears in two tactics only gets scored in one, and your merge counts in Step 3 will be silently wrong.

## Step 3 — Merge the group layers into a single threat layer

1. Click **Create New Layer** → **Create Layer from Other Layers**.
2. Pick the same domain and ATT&CK version as your group layers. Navigator shows each open layer's variable (`a`, `b`, `c`, …) in yellow on its tab.
3. In **score expression**, enter the sum of your group layers — for example `a+b+c+d` for four groups.
4. Name the result something like `threat-model-2026Q3`. Each technique's score is now *how many of your scoped groups use it* — the **Exposure** lens from family 2 of the [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md).
5. Apply your platform **filters** from Step 1 (layer controls), and set a **color setup** gradient from white (low) to red (high).

**Checkpoint:** A single layer where a score of `4` means all four of your groups use the technique, and unscored cells mean none do.

**Watch out:** Layers must share the same domain and ATT&CK version to be combined. If any tab was created on an older version, run it through Navigator's layer upgrade interface first (it opens automatically when a stale layer loads — step through the changed techniques and click **done**).

## Step 4 — Overlay this library's control-coverage layer

Now bring in the defensive side: how deeply NIST 800-53 controls (via CTID mappings) cover each technique.

1. In a new Navigator tab, choose **Open Existing Layer** → **load from URL** and paste the master coverage layer: `https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json` (it is also the first row of the [Navigator layer index](/navigator/index.md), with a one-click load link).
2. The layer scores 470 techniques by NIST 800-53 R5 control depth. Use the score-interpretation table in the [layer index](/navigator/index.md): roughly, 20+ means broad control coverage, 1–9 means thin.
3. The layer was built against an earlier ATT&CK version, so Navigator opens its layer upgrade interface — accept the upgrade to the current version, review the techniques it flags as added, changed, or removed, and click **done**. You need it on the same version as your threat layer before Step 5.

**Checkpoint:** Two aligned layers open side by side — threat scores in one tab, NIST control depth in the other, both on the same ATT&CK version.

**Watch out:** Absence of a score here is a *data-coverage* gap, not automatically a security gap — 223 of 691 Enterprise techniques simply have no CTID-mapped NIST control (see the framework blind-spots layer in the [layer index](/navigator/index.md)). Note them; don't panic over them.

## Step 5 — Compute the priority-gap layer

This is the money step: techniques that are **heavily used and thinly covered**.

1. **Create New Layer** → **Create Layer from Other Layers** again. Say your merged threat layer is `a` and the coverage layer is `b`.
2. Enter the score expression: `a * (1 + 1 / (b + 1))`
   This is the library's priority formula from the [ATT&CK Priority Gap Analysis](/scores/attack_priority_gaps.md) — group count amplified by inverse control depth. A technique four of your groups use with zero mapped controls scores `8.0`; the same technique with 19 controls scores `4.2`.
3. Set the gradient (green low → red high) in **color setup**, and use the **sorting** control to sort techniques by score, descending.
4. Read the top of the sorted list. That is your draft gap list.

**Checkpoint:** A layer named like `priority-gaps-2026Q3` whose reddest cells are simultaneously popular with your adversaries and under-covered by controls.

**Watch out:** Gradient shading is normalized to the maximum in view — the doctrine's "normalize thoughtfully" rule. If you change platform filters after scoring, the colors re-normalize and two screenshots become incomparable. Lock filters before you export anything.

## Step 6 — Cross-check the gaps in ATTACK-Navi's heatmap modes

Navigator gave you one composite view. [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) — this library's companion workbench — lets you re-color the same matrix through every lens family without rebuilding layers.

1. Run it locally (commands from the official README):

   ```bash
   git clone https://github.com/TeamStarWolf/ATTACK-Navi.git
   cd ATTACK-Navi
   npm install
   npx ng serve
   ```

   Then open `http://localhost:4200`. Use the command palette (`Ctrl+K`) to find groups and techniques fast.
2. Walk your draft gap list through the analysis workflow from the [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md), one heatmap mode per question:
   - **Frequency** / **Exposure** — does the technique matter beyond your scoped groups?
   - **NIST 800-53** / **Coverage** / **Controls** — confirm the control thinness you computed in Step 5.
   - **KEV** / **EPSS Probability** / **CVE** — is there active exploitation pressure? Treat [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) hits as a priority multiplier, and read probabilities against [FIRST's EPSS model](https://www.first.org/epss/).
   - **Sigma** / **CAR** / **Detection** — is published detection logic available even where controls are thin?
   - **Atomic** — can you *validate* detection with an Atomic Red Team test? (Stay at the level of test IDs; execution belongs in an approved purple-team exercise.)
3. Annotate your draft list: for each top technique, record KEV/EPSS pressure and detection availability. Import or export ATT&CK Navigator layer JSON through the Reports workspace's **Export Hub** if you want your Step 5 layer inside ATTACK-Navi.

**Checkpoint:** Each draft gap now carries three extra facts: exploitation urgency, detection-content availability, and validation-test availability.

**Watch out:** Counts are availability, not proof. "12 Sigma rules exist" does not mean you run any of them — it means closing the gap is cheap, not that it is closed.

## Step 7 — Reconcile against the library's precomputed scores

1. Open the [ATT&CK Priority Gap Analysis](/scores/attack_priority_gaps.md) top-75 table (machine-readable copy: `scores/attack_priority_gaps.json`). It ranks all Enterprise techniques by the same formula you used, but with *all* tracked groups counted.
2. Compare your top 20 against it. Three outcomes, all useful:
   - **On both lists** — a consensus gap; highest confidence.
   - **High on yours, absent from the global top 75** — your differentiated exposure; lead your report with these, they are what a generic benchmark misses.
   - **High globally, absent from yours** — either your scoped groups genuinely don't use it, or your scoping was too narrow. Re-check Step 1 before dismissing it.
3. If you also run the vendor stack modeled in this library, compare tactic-level numbers with the [Coverage Gap Analysis](/scores/coverage_gaps.md) and its `scores/tactic_coverage.json` — Collection, Discovery, and Defense Evasion are its standing critical gaps and deserve suspicion in any stack.

**Checkpoint:** Every technique on your list is labeled consensus, differentiated, or descoped-with-reason.

**Watch out:** The precomputed reports state their ATT&CK and data versions in their headers. If yours differ, expect small rank shifts — reconcile direction, not decimal places.

## Step 8 — Write the ranked gap list and assign owners

Turn the layer into a work queue. One row per gap, ranked by your Step 5 score, adjusted upward for KEV/EPSS pressure:

| # | Technique | Why it's a gap | Gap type | Owner | Next action | Target |
|--:|---|---|---|---|---|---|
| 1 | T1547.001 Registry Run Keys / Startup Folder | 3 of 4 scoped groups; 0 NIST controls | Detection | Detection engineering | Deploy autorun-key Sigma rules; validate with Atomic test | Q4 |
| 2 | T1078 Valid Accounts | All 4 groups; controls exist but unvalidated | Validation | IAM + purple team | Atomic-validate alerting on anomalous logons | Q4 |
| 3 | T1082 System Information Discovery | 55 groups globally; 0 controls, telemetry-only | Control + Detection | Endpoint engineering | UEBA discovery-pattern analytics on existing logs | Q1 |

Rules that keep the register honest:

1. **Classify the gap type** — *control* (nothing prevents it), *detection* (nothing sees it), or *validation* (something should see it, never tested). The lens families in the [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md) map one-to-one onto these types.
2. **One named owner per row.** A team name is acceptable; "security" is not.
3. **Next action, not aspiration.** Pull concrete detection candidates from the [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) and mitigation options from the [ATT&CK Mitigations Reference](/ATTACK_MITIGATIONS_REFERENCE.md).
4. Cap the register at what the owners can close in two quarters — usually 10–20 rows. The layer keeps the long tail for next time.

**Checkpoint:** A ranked table where every row has a technique ID, a gap type, an owner, and a dated next action.

**Watch out:** Resource Development and Reconnaissance techniques (T1588.002 tops the global list) mostly happen off your infrastructure — no internal control can reach them. Route them to threat intel as watch items instead of assigning impossible engineering work.

## Step 9 — Export, share, and schedule the re-run

1. In Navigator's layer controls, use **download layer as json** on the Step 5 layer — this JSON is the assessment's reproducible artifact. Commit it beside the others under `navigator/` in your fork or team repo, named with the quarter.
2. Use **export to excel** for the working copy owners will edit, and **render layer to SVG** for the leadership snapshot.
3. Schedule the re-run: quarterly, or immediately when ATT&CK ships a new version or your threat model changes. Re-running is Steps 2–5 with the saved JSON reloaded via **Open Existing Layer**.
4. Measure closure over time: combine last quarter's layer (`a`) and this quarter's (`b`) with the score expression `a-b` — positive cells are gaps you closed, negative cells are new exposure. Feed the trend into your program metrics per the [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md).

**Checkpoint:** A committed layer JSON, an Excel register in owners' hands, an SVG in the deck, and a calendar entry for the next run.

**Watch out:** An exported layer pins an ATT&CK version. When you reload it after a version bump, run the layer upgrade interface *before* comparing scores, or renamed and revoked techniques will masquerade as closed gaps.

## What good looks like

- **Scoping is written down** — every group has a one-line rationale, so next quarter's analyst can challenge it.
- **Your numbers reconcile** — your top gaps either appear in the [ATT&CK Priority Gap Analysis](/scores/attack_priority_gaps.md) top 75 or you can say why they are sector-specific.
- **Every gap is typed** — control vs. detection vs. validation — because the fix, the owner, and the cost differ for each.
- **No row without an owner and a dated action.** A heatmap without a work queue is wall art.
- **The artifact is reproducible** — layer JSON committed, formula recorded, versions noted. Anyone can regenerate your reddest cell.
- **You honored the two doctrine caveats** — availability counts were never reported as deployed coverage, and missing mappings were flagged as data gaps, not breaches-in-waiting.

## Go deeper

- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md) — the knowledge graph and per-technique coverage stack this assessment walks
- [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md) — all lens families and the full analysis workflow
- [Controls Mapping](/CONTROLS_MAPPING.md) and [Coverage Schema](/COVERAGE_SCHEMA.md) — how the vendor → control → technique edge tables behind the layers are built
- [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) — multi-platform detection queries for closing the detection-type gaps
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) — SSVC/KEV/EPSS depth for the urgency multiplier in Step 6
- [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) — turning quarter-over-quarter closure into program KPIs
- [ATT&CK Navigator usage documentation](https://github.com/mitre-attack/attack-navigator/blob/master/USAGE.md) — official reference for every control named above
- [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) — the NIST 800-53 ↔ ATT&CK mappings the coverage layer is sourced from
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — the KEV feed behind the urgency lens
- [FIRST EPSS](https://www.first.org/epss/) — the exploit-prediction model behind the probability scores

*Guides are procedures, not doctrine — verify every command and menu path against the current official documentation before you rely on it in production.*
