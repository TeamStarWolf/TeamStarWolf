# ATT&CK Matrix Analysis Reference

> **What this is.** A catalog of the analytic *lenses* you can lay over a MITRE ATT&CK matrix to turn it
> from a static list of techniques into a decision tool. Each lens recolors every technique by a different
> security dimension — mitigation depth, threat activity, detection coverage, vulnerability exposure,
> compliance, or composite risk — so a different question gets answered by the same matrix. These are the
> 24 heatmap modes implemented in [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi); the model
> generalizes to any Navigator-style workflow.

| | |
|---|---|
| **Read this when** | choosing which heatmap mode answers your coverage question, prioritizing techniques by threat activity or exploitation urgency, sanity-checking what a gradient score does and does not prove |
| **Start at** | [An analysis workflow](#an-analysis-workflow), [Lens family 1 - Mitigation & control coverage](#lens-family-1-mitigation-amp-control-coverage), [Reading the scores safely](#reading-the-scores-safely) |
| **Pairs with** | [Threat-Informed Defense Reference](THREAT_INFORMED_DEFENSE_REFERENCE.md), [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md), [Security Metrics Reference](SECURITY_METRICS_REFERENCE.md), [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) |

A single coverage view answers one question. Real coverage analysis means switching lenses: *are we
mitigated?* → *are we detected?* → *have we validated?* → *is this under active exploitation?* → *what is
the composite risk?* The lenses below are grouped by the question they answer.

**How scoring works.** Most lenses are *gradient* modes — a technique's cell is shaded from a count or
probability, normalized against the maximum in view. A few are *categorical* (discrete states like
implemented/planned/none). Combine lenses with filters (by threat group, platform, or data source) to
narrow the matrix to your situation before coloring it.

---

## Lens family 1 — Mitigation & control coverage

*"How well is this technique defended by controls and mitigations?"*

| Lens | Question it answers | Score |
|---|---|---|
| **Coverage** | How many ATT&CK mitigations map to this technique? | Count of mapped ATT&CK mitigations (0–4+) |
| **Controls** | Is the technique covered / planned / uncovered by our security controls? | Categorical: covered · planned · none |
| **Status** | What is our implementation status for this technique's mitigations? | Best status across mitigations: implemented > in-progress > planned > not-started > none |
| **NIST 800-53** | How many NIST 800-53 controls address this technique? | Count of mapped NIST controls (CTID) |
| **CRI Profile** | How many Cyber Risk Institute Profile controls map here? | Count of CRI Profile controls |
| **D3FEND** | How many defensive countermeasures exist for this behavior? | Count of D3FEND countermeasure techniques |
| **Engage** | How many adversary-engagement/deception options apply? | Count of MITRE Engage activities |

**Use it to:** find techniques with *zero* mitigations (the classic red-cell gap analysis), report
implementation progress to a program owner, or decide where to add a control. The
[master coverage layer](navigator/teamstarwolf_vendor_coverage.json) in this repo is a NIST-control-depth
view of this family.

---

## Lens family 2 — Threat activity & exposure

*"How much do real adversaries use this technique?"*

| Lens | Question it answers | Score |
|---|---|---|
| **Frequency** | How many known threat groups use this technique overall? | Count of unique ATT&CK groups (bucketed) |
| **Exposure** | How many of *my selected* threat actors use it? | Count of selected threat groups using the technique |
| **Software** | How rich is the tooling ecosystem for this technique? | Count of ATT&CK software (malware/tools) implementing it |
| **Campaign** | Has it shown up in real named campaigns? | Count of ATT&CK campaigns using it |
| **Intelligence** | Do we have live intel signal for this technique? | `has-MISP (0/1) + selected threat-group count` |

**Use it to:** prioritize detection investment on the most *popular* techniques, or — after selecting the
threat actors relevant to your sector in a filter — switch to **Exposure** to see where *your* adversaries
concentrate. High activity + thin mitigation (see family 1) is the definition of a priority gap.

---

## Lens family 3 — Vulnerability exposure & urgency

*"How exploitable and urgent is this technique in the real world right now?"*

| Lens | Question it answers | Score |
|---|---|---|
| **CVE** | How many vulnerabilities are associated with this technique? | Count of CVEs (CTID ATT&CK↔CVE dataset) |
| **KEV** | Is it tied to *known-exploited* vulnerabilities? | Count of CISA KEV CVEs mapped to the technique |
| **EPSS Probability** | How likely are its CVEs to be exploited? | Average EPSS probability (0–1) across mapped CVEs |

**Use it to:** convert generic ATT&CK coverage into urgency. A technique carrying KEV-backed CVEs with high
EPSS should outrank an equally-covered technique with no active exploitation pressure. Treat KEV as a
*priority multiplier*, not a footnote.

---

## Lens family 4 — Detection engineering

*"If this happened, would we see it — and with what?"*

| Lens | Question it answers | Score |
|---|---|---|
| **Sigma Rules** | Is there portable detection logic published for this technique? | Count of Sigma rules |
| **Elastic Rules** | How many maintained Elastic detections cover it? | Count of Elastic Detection Rules |
| **Splunk Detections** | How many Splunk Security Content detections cover it? | Count of Splunk ESCU detections |
| **CAR Analytics** | Is there a vendor-neutral analytic with data-model context? | Count of MITRE CAR analytics |
| **Atomic Tests** | Can we *exercise* the technique to validate detection? | Count of Atomic Red Team tests |
| **Detection (composite)** | Overall detection strength across sources | Weighted: `sigma×3 + d3fend×2 + car×2 + atomic×1` |

**Use it to:** find techniques with *no published detection logic* (a detection gap distinct from a control
gap), and to pair detection with validation. The [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md)
provides concrete, multi-platform queries for a starter set of high-value techniques.

---

## Lens family 5 — Breach patterns & composite risk

*"Putting it together — where should I actually spend effort?"*

| Lens | Question it answers | Score |
|---|---|---|
| **VERIS Actions** | How does this technique map to real incident action patterns? | Count of VERIS action mappings |
| **Risk** | Which techniques are heavily targeted *and* poorly mitigated? | `groupCount × (1 + 1/(mitigationCount+1))` |
| **Unified Risk** | A single composite score across dimensions | Composite 0–100 blending coverage, threat, detection, exposure, and controls |

**Use it to:** drive risk-based prioritization. **Risk** amplifies techniques that many groups use but few
mitigations address; **Unified Risk** rolls multiple lenses into one rank so leadership can see the
top-priority techniques without switching modes.

---

## An analysis workflow

A repeatable pass across the lenses:

1. **Filter first.** Narrow to your platforms and, if relevant, your threat actors.
2. **Frequency / Exposure** — identify the techniques that matter for you.
3. **Coverage / NIST / Controls** — of those, which are under-mitigated?
4. **CVE / KEV / EPSS** — of the gaps, which are under active exploitation pressure?
5. **Sigma / CAR / Detection** — do we at least have a chance of *seeing* the unmitigated ones?
6. **Atomic** — validate detection on the survivors.
7. **Risk / Unified Risk** — sanity-check your priority list against the composite score.
8. **D3FEND / Engage** — choose the next defensive action for each top gap.

Export the resulting technique set as an ATT&CK Navigator layer to track it over time and share it with
your team.

---

## Reading the scores safely

- **Counts are availability, not proof.** "5 Sigma rules exist" ≠ "we run them and they work." Detection
  and control counts measure what *could* cover a technique; **Status** and **Atomic** validation measure
  what actually does.
- **Absence of a score is a data-coverage gap, not necessarily a security gap.** Some techniques legitimately
  have no NIST mapping or no published Sigma rule; verify before concluding you're exposed.
- **Normalize thoughtfully.** Gradient shading is relative to the maximum in view; changing filters changes
  the shading. Compare like with like.

---

## Related references

- [Threat-Informed Defense Reference](THREAT_INFORMED_DEFENSE_REFERENCE.md) — the knowledge-graph and data-source model behind these lenses
- [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) — multi-platform detections per technique
- [Security Metrics Reference](SECURITY_METRICS_REFERENCE.md) — turning coverage into program KPIs
- [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) — CVSS/EPSS/KEV prioritization
- [Controls Mapping](CONTROLS_MAPPING.md) · [Coverage Schema](COVERAGE_SCHEMA.md) · [Navigator layers](navigator/)
- [ATTACK-Navi workbench](https://github.com/TeamStarWolf/ATTACK-Navi) — reference implementation of all 24 lenses
