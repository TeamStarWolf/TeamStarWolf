# IMPROVEMENT PLAN: Case Studies

*Companion to `CRITIQUE-CASE-STUDIES.md`. This turns every criticism into a sequenced, file-level plan. The bar is "to my expectation": a reader with one hour, not one hundred, can find the right study, trust the grading at a glance, and come away with the core facts — while the deep evidentiary body still exists for those who want it.*

## The key realization

You have already **built most of the machinery** these fixes need. The gap is activation and curation, not construction:

- **`data/doc_takeaways.draft.yaml`** — 1,051 lines of drafted, quote-validated key takeaways (3–5 per page, one sentence each), status *"owner review pending,"* **never rendered on any page.** This is the skim-layer / standalone-summary the critique asks for. It exists. It is off.
- **`reviews:` in `data/doc_meta.yaml`** — a fully designed, batched whole-page review system ("batches of ~20, batch 1 = most-read references"). Deliberately all-null, which is why all 117 cards say *"No review recorded yet."* The infrastructure is done; the process hasn't been run.
- **`scripts/check_voice.py`** — a working prose linter with a hype-word banlist and process-note rules. It does **not** yet validate the evidence-grade vocabulary — the one hook the legend fix needs.
- **`scripts/build_doc_meta.py`, `scripts/export_case_study.py`, `TIMELINE.md` app, `data/case_studies.yaml`** — structured data (dated events, sectors, CVEs, ATT&CK groups) already exists per study, unused for visuals.

So the plan below is mostly *switch it on, in the right order, and close four genuine gaps* (curation, grade-tag density, visuals, length).

---

## Phase 0 — Credibility fixes (half a day, do first)

**Why first:** the grade-legend mismatch (critique A3) is the single most credibility-damaging defect and the cheapest to fix. Fix it before anything else so the rest of the work builds on an honest foundation.

**Moves**
1. Add **Inferred** to the grade legend table in `case-studies/README.md` → `## Method`, and reconcile all four definitions (Confirmed, Reported, Inferred, Demonstrated) with how the prose actually uses them. "Inferred" is used 1,344× and is currently undefined there.
2. Add a **grade-vocabulary check to `scripts/check_voice.py`**: flag any `(Grade …)` label that is not one of the four canonical grades, and (optional) flag a study that introduces a grade the legend doesn't define. Wire it into the existing `--check` CI path.
3. Publish the definitions once, centrally (a `GRADING.md` or an anchor in README), and have every study link to it instead of re-explaining.

**Acceptance:** `grep -ohE "\((Confirmed|Reported|Inferred|Demonstrated)" case-studies/*.md | sort -u` ⊆ legend; CI fails on an undefined grade label.

---

## Phase 1 — Build a front door & turn on the skim layer (1–2 days)

**Why:** critique A1/A4/A5/D1/D7. 119 equal doors, no lobby. You already drafted the lobby's contents.

**Moves**
1. **Curate the index.** Rewrite the top of `case-studies/README.md` with a hand-picked **"Start here — 10 essential studies,"** grouped by reader goal (*understand supply-chain risk* / *brief an exec* / *study an actor* / *work a live CVE*). SolarWinds, Stuxnet, Log4Shell, Change Healthcare, XZ, the ransomware ecosystem, APT41, the AI-threats study are the obvious marquee set.
2. **Demote the backfill.** Collapse the **34 `CHRONICLE_YEAR` files** into a `<details>`-folded *"Annual record (reference)"* section below the curated set, so the flagships stop drowning. (`doc_meta.yaml` already has a `fold:` mechanism — reuse it.)
3. **Approve & render the takeaways.** Run the process the draft file documents: move a first batch (the ~20 marquee case studies) from `doc_takeaways.draft.yaml` into `data/doc_takeaways.yaml`, set `reviewed:` dates, run `scripts/build_doc_meta.py`. A **"Key takeaways" box now renders** at the top of each study — the skim layer, live.
4. **Index shows the takeaway, not the run-on.** Replace each 150–260-word "What it covers" cell with the study's first takeaway (one sentence) + a link. Cap any remaining prose cell at two sentences.

**Acceptance:** README first screen is curated and goal-grouped; each marquee study renders a Key-takeaways box; no index cell exceeds two sentences.

---

## Phase 2 — Get the grade tags out of the reading line (2–4 days; biggest readability win)

**Why:** critique A2/C1. ~1 inline grade tag every 65 words is the texture that makes the prose unreadable. The **slide decks already prove the fix**: one batched `Grades:` sentence per section, clean prose.

**Moves**
1. Write `scripts/degrade_inline.py` (or extend `export_case_study.py`): parse the `(Grade [refs])` and `[n]` spans per section, collect them into **one "Grades:" line per section** (decks' pattern) plus **numbered endnotes**, and strip them from the sentence body. The grades are preserved — just relocated out of the reading path.
2. **Pilot on 3 flagships** (Change Healthcare, SolarWinds, Log4Shell), eyeball the output, tune, then batch across all 119.
3. Keep a machine-readable grade map (per claim → grade → sources) in a sidecar so nothing is *lost*, only moved; the body text stays auditable.

**Acceptance:** inline grade tags in the reading line drop ~10×; every study still carries its grades (section headers + endnotes); decks and studies now share one grading presentation.

---

## Phase 3 — Visuals (1 week, flagships first)

**Why:** critique B1/C4. Only 14 of 119 studies have any image; the data for figures already exists structured in `data/case_studies.yaml`.

**Moves**
1. Add `scripts/build_case_figures.py`: from each study's YAML (dated events, sectors, CVEs, impact numbers), auto-generate **(a) a timeline graphic and (b) an impact/attribution figure** as SVG/PNG into `case-studies/assets/`, captioned with source.
2. Inject the two figures into the study Markdown + the PDF export; add **≥1 real chart** to each deck (they carry only a logo today).
3. Do the **~15 marquee studies first**, not all 119. Chronicles can share a single generated year-bar.

**Acceptance:** every flagship study has ≥2 sourced figures; every flagship deck has ≥1 chart.

---

## Phase 4 — Length discipline: split the monsters (ongoing policy + 2–3 days initial)

**Why:** critique A1/B4/D5. A 72,315-word "case study" is a book mis-filed.

**Moves**
1. **Policy:** anything filed as a *case study* ≤ ~4,000 words. Overflow splits into a **"case" (the narrative) + a "reference appendix"** (full MITRE mappings, exhaustive timelines, source tables).
2. Repackage **`THE_RECORD_AND_THE_WINDOW.md`** as a clearly labeled *Thesis / long-form* — its own section, not the case-study table.
3. Split the longest chronicles (2024–2026, each 20k+ words) into case + appendix.
4. Add a **word-count gate** to `scripts/build_stats.py` or the `export_case_study.py --check`: warn >4,000 words in a case-study-typed file.

**Acceptance:** no file typed "case study" exceeds ~4,000 words; the thesis is labeled and shelved as long-form; CI warns on overflow.

---

## Phase 5 — Run the review process you designed (continuous)

**Why:** critique B3. The `reviews:` system is built and empty. An empty rigor signal is worse than none.

**Moves**
1. Execute the batched whole-page reviews already planned in `doc_meta.yaml` (batch 1 = most-read). Populate `reviewed:` so "Last reviewed" stops being blank on 100% of pages.
2. Tie review cadence to the existing 90-day "Due for review" computation.

**Acceptance:** "No review recorded yet" disappears from the marquee set first, then rolls out by batch.

---

## Guardrails to keep it fixed (add to CI once, pay off forever)

- Grade label ∈ legend (Phase 0).
- No case-study file > ~4,000 words (Phase 4).
- Every study has an approved takeaways entry (Phase 1) **and** a tag-free ≤300-word standalone summary.
- Every flagship has ≥1 generated figure (Phase 3).
- Index cells ≤ 2 sentences (Phase 1).

## Suggested order & rough effort

| Phase | What | Effort | Unblocks |
|---|---|---|---|
| 0 | Grade legend + linter | ~0.5 day | credibility |
| 1 | Front door + render drafted takeaways + index de-run-on | 1–2 days | discoverability, skim |
| 2 | De-noise grade tags (script + batch) | 2–4 days | readability (biggest) |
| 3 | Figures for flagships | ~1 week | visual product |
| 4 | Split monsters + word-count gate | 2–3 days + policy | length |
| 5 | Run review batches | continuous | rigor signal |

Phases 0 and 1 alone move the product from "unusable pile" to "navigable, trustworthy, skimmable" — that's the highest-leverage week. Everything after is depth.

## What "to my expectation" means (the bar to measure against)

1. A newcomer lands on the index and within 30 seconds knows the 10 studies that matter and which one fits their goal.
2. Opening any flagship, the first screen is a Key-takeaways box and a tag-free summary — the core in 3 minutes, the body for those who stay.
3. The prose reads as prose; grades live in section headers and endnotes, not mid-sentence.
4. The grade legend matches the labels, enforced by CI.
5. Every flagship shows its timeline and impact as a picture, not only a paragraph.
6. Nothing filed as a "case study" takes longer than ~18 minutes to read; the one book is labeled a book.
7. "Last reviewed" shows a real date on the studies people actually open.
