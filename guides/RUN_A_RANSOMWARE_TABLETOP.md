# Run a Ransomware Tabletop Exercise

> **By the end of this guide you will have planned, facilitated, and closed out a CISA CTEP-based ransomware tabletop — ending in a signed-off corrective-action plan with named owners and due dates, not a pile of sticky notes.** This is for the security lead, continuity planner, or IT manager who has been told "we should exercise the ransomware plan" and needs to run one properly, without a consultant.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| ~12 weeks part-time planning, one ~4-hour session, after-action closes ~8 weeks later | Moderate — no tooling to install; facilitation and follow-through discipline are the hard parts | The free CISA CTEP package, your current IR/DR/BC plans, an executive sponsor, a facilitator, a room with A/V | A customized situation manual, a facilitated tabletop, and an HSEEP-style After-Action Report / Improvement Plan (AAR/IP) with owners and dates |

## Before you start

- [ ] Read the **Testing tiers** section of [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md) — where a tabletop sits on the exercise ladder and what it can and cannot prove.
- [ ] Read the **Exercising readiness** and **Payment policy considerations** sections of [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md) — the questions a ransomware tabletop exists to force.
- [ ] Have the plans under test in hand: your IR plan, DR/continuity plan, and the ransomware playbook pattern in [IR Playbooks](/IR_PLAYBOOKS.md). A tabletop tests plans as they exist today — if there is no plan, run a workshop to write one first.
- [ ] Secure an executive sponsor who will receive the findings and own closure reporting.
- [ ] Confirm ~3 months of lead time. The [CTEP Exercise Planner Handbook](https://www.cisa.gov/resources-tools/resources/ctep-package-documents) assumes planning begins "at least three months before the desired exercise date."
- [ ] Have Microsoft Word or an equivalent DOCX editor — the CTEP situation manuals ship as customizable Word documents.

## Step 1 — Define what the exercise must prove

Decide the variant before anything else. The library's recommended cadence is one **executive tabletop** per year (declaration authority, communications, the payment decision) and one **technical exercise** per year (IR/recovery coordination). Pick one — a session that tries to be both serves neither audience.

Write 3–5 exercise objectives. The CTEP situation manual ships with proposed objectives you will adapt, but draft yours first, from the places ransomware breaks classical DR assumptions (see [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)):

- Backups are gone too — T1490 Inhibit System Recovery succeeded. Who decides the last clean restore point, and on what evidence?
- Identity is down — domain controllers are encrypted. Can anyone authenticate, and does the recovery plan work without AD?
- Corporate comms are unavailable or untrusted — does the team know the out-of-band channel?
- Exfiltration is confirmed — who briefs customers, regulators, and the board, on what clock?
- The payment question — who decides, who must be consulted, where is the OFAC screening step?

Each objective must be falsifiable: "Validate the declaration criteria for a ransomware event" can fail and produce a finding; "raise awareness" cannot.

**Checkpoint:** A one-page exercise charter — variant, 3–5 objectives, target month, sponsor's name — approved by the sponsor.

**Watch out:** Objectives written to pass ("confirm our plan works") produce a feel-good session and an empty improvement plan. Write objectives around the assumptions you suspect are fiction.

## Step 2 — Download the CTEP package and pick your scenario

CISA's [Tabletop Exercise Packages (CTEP)](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages) are free, self-run exercise kits in three categories: cybersecurity, physical security, and cyber-physical convergence. You need two downloads:

1. **The situation manual (SitMan).** From the [Cybersecurity Scenarios page](https://www.cisa.gov/resources-tools/resources/cybersecurity-scenarios), download the **Ransomware** situation manual (DOCX, dated September 2023 as of this writing). If a sector variant fits better, take it instead — Healthcare and Public Health, K-12, Local Governments, Water & Wastewater Systems, Financial Services, and others are listed on the same page. For the executive variant, the **Executives and Senior Leadership** SitMan (August 2024) is written for exactly that audience.
2. **The supporting package.** From the [CTEP Package Documents page](https://www.cisa.gov/resources-tools/resources/ctep-package-documents), download all eight: Welcome Letter, Exercise Planner Handbook, Facilitator/Evaluator Handbook, Invitation Letter Template, Exercise Brief Slide Deck Template, Participant Feedback Template, Planner Feedback Form, and the AAR-IP Template.

Read the Exercise Planner Handbook end to end — its "14 Key Steps" sequence is the skeleton this guide hangs the ransomware specifics on. Questions go to cisa.exercises@cisa.dhs.gov.

**Checkpoint:** A working folder containing one SitMan DOCX plus the eight package documents, and you can name the three modules the exercise will run.

**Watch out:** CISA retired six facilitated assessment programs in 2026, and the library's standing caveat applies: the CTEP pages were live as of September 2026, but verify before building an annual program on them — and keep a local mirror of the package once downloaded.

## Step 3 — Build the planning team and cast the roles

Form a small **exercise planning team (EPT)**: security, IT/communications, business continuity, operations, and a spokesperson or public information officer. For a ransomware scenario add legal counsel and whoever owns the cyber-insurance relationship — the payment-policy module is theirs. Planning-team members learn the scenario in advance, so **EPT members must not be players**.

Cast the delivery roles the handbook defines:

| Role | What they do | Who fits |
|---|---|---|
| **Facilitator** | Presents the modules, poses discussion questions, keeps time and focus | Someone comfortable moderating peers; not the plan's author if you can avoid it |
| **Evaluators / data collectors** | Document player discussion and whether it conforms to plans, policies, and procedures | People who know the plans well enough to notice a deviation |
| **Players** | Discuss their real roles against the scenario | Must have authority to speak for their function |
| **Observers** | Watch; contribute only if the facilitator calls on them | Interested stakeholders, auditors, next year's planners |

Pick a format: **plenary** (one group, one facilitator, workable to roughly 25–30 players) or **multi-table** (tables by function, each ideally with its own facilitator and evaluator, reconvening to brief out). Executive tabletops are almost always plenary.

**Checkpoint:** A roster with a name against every role, the facilitator confirmed for the date, and at least one evaluator per table.

**Watch out:** Players who lack authority turn every hard question into "I'd have to check with my boss" — which tells you nothing except that you invited the wrong people. Invite the boss.

## Step 4 — Run the planning meetings on the CTEP timeline

Work backward from the exercise date using the handbook's milestones:

| When | Milestone | What gets decided |
|---|---|---|
| ~3 months out | **Concept & Objectives Meeting** | EPT confirmed; scope, objectives, and timeline agreed |
| ~2.5 months out | **Initial Planning Meeting** (combinable with C&O) | Scenario, format, venue, schedule, participant list |
| 6–8 weeks out | **Midterm Planning Meeting** | Staffing confirmed; SitMan scenario and discussion questions reviewed; invitation process set |
| ~6 weeks out | **Invitations sent** | Use the Invitation Letter Template; include access/parking details |
| 2 weeks out | **Final Planning Meeting** | Final document review; no design or scope changes after this point |
| 1 week out | **Print** | One SitMan per participant plus ~20% spares; Facilitator & Evaluator Handbook for facilitators and evaluators only |

Book a room large enough for everyone, with working A/V and ideally access the evening before for setup. If the session is remote, rehearse the platform with the facilitator and evaluators in advance.

**Checkpoint:** Final Planning Meeting held, documents frozen, logistics locked, invitations accepted by the players who matter.

**Watch out:** The Exercise Planner Handbook and the Facilitator & Evaluator Handbook are for planners and facilitators only — never distribute them to players, or you hand out the answer key.

## Step 5 — Write the injects tied to your environment

The SitMan is a template: yellow-highlighted (SitMan) and red-font (slide deck) fields mark everything you must customize. Generic scenarios produce generic shrugs — replace placeholders with your reality:

- Name your actual systems: the backup platform, the EDR, the identity platform, the ERP the business bleeds without.
- Use your declared numbers: the real RTO/MTD for the affected services, your insurer's notification deadline, your regulators' clocks (see [IR Playbooks](/IR_PLAYBOOKS.md) for the notification-deadline reference).
- Anchor the scenario clock badly on purpose: Friday 5 p.m. before a holiday weekend is the realistic case.

Then script the **injects** — the situation updates the facilitator drops into each module to force the questions technology cannot answer. Keep them at effect level (a technique ID at most, per this library's defensive scope — never operational tradecraft). Proven ransomware injects:

1. The backup console is unreachable and last night's jobs were deleted (T1490) — the restore conversation just changed.
2. Both domain controllers at the primary site are encrypted mid-Module Two — authentication, and your bridge call invite, just died.
3. A leak-site post names your organization with sample files — exfiltration is now confirmed and public.
4. The affiliate emails three of your customers directly demanding they pressure you — whose phone rings, and what do they say?
5. Your insurer's approved negotiator and your outside counsel disagree on engaging the actor — who decides?
6. Corporate email and chat are declared untrusted — move the response to the out-of-band channel, right now, in the room.

Sync every change across the SitMan, the Exercise Brief Slide Deck, and the AAR/IP shell, and strip all highlighting before printing. Per the handbook, hold ~6 backup questions in the Facilitator & Evaluator Handbook (in italics, not in the SitMan) for modules that run fast.

**Checkpoint:** A customized SitMan with zero highlighted fields, injects that name your real systems, and every discussion question traceable to one of your objectives.

**Watch out:** Do not write injects your plan already answers cleanly end to end — you will spend three hours confirming the easy 80%. Spend the injects on the assumptions the [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md) flags as cyber-broken: backups, identity, comms, declaration.

## Step 6 — Facilitate the session without steering it

Run the handbook's recommended flow, scaled to your slot (CTEP allots about four hours): welcome and player briefing, **Module One: Threat**, **Module Two: Incident and Aftermath**, **Module Three: Business Continuity and Recovery**, hotwash, closing comments, then a facilitator/evaluator debrief.

Open with ground rules: this is a no-fault, low-stress discussion; respond from plans and capabilities as they exist today; nothing deploys; there are no tricks in the scenario. Then hold the facilitation line:

- Pose the question, then let silence do the work. The first uncomfortable pause is usually where the finding lives.
- Direct questions to roles, not the room: "Legal — the leak-site inject just landed. What is your next call?"
- When discussion stalls because the plan has no answer, **that is the product**. Say "captured — moving on," make sure an evaluator logged it, and continue. Do not rescue the room with the answer.
- Park rabbit holes visibly and return to the module clock. Cutting discussion questions beats cutting Module Three — recovery is where the BCDR findings are, and it is always the module that gets squeezed.

Evaluators capture who said what, which plan was invoked, and where discussion diverged from the written procedure. Close with the hotwash — each function states its top strength and top gap while memory is fresh — and collect Participant Feedback Forms before anyone leaves the room.

**Checkpoint:** Evaluator notes covering every objective, a hotwash list of strengths and gaps, and a stack of completed feedback forms.

**Watch out:** A facilitator who answers players' questions converts the exercise into a training session — the AAR will then measure the facilitator's knowledge, not the organization's readiness. If the facilitator wrote the plan, this failure mode is nearly guaranteed; brief them on it explicitly, or pick someone else.

## Step 7 — Turn findings into a corrective-action plan

The exercise is not over when the room empties — the handbook budgets roughly eight more weeks:

1. **Draft the AAR/IP** within 3–4 weeks, using the AAR-IP Template. Consolidate evaluator notes, hotwash items, and feedback forms into strengths, areas for improvement, and draft corrective actions. Circulate to the EPT for comment before the meeting.
2. **Hold the After-Action Meeting** at 5–6 weeks. Walk the draft item by item and reach consensus. Per the handbook, this is where participants "develop concrete deadlines" and "identify specific corrective action owners / assignees" — do not leave the room with an unowned or undated action.
3. **Finalize and distribute** within two weeks of the meeting, and file the corrective actions in your real work tracker, not the exercise folder.

Then close the loop the way the library's governance section demands: update the plans that failed (a plan review is triggered "after every exercise"), report closure status to the sponsor on a cadence, feed the results into your program numbers — exercise cadence and finding-closure rate are standing metrics in [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), with formulas in [Security Metrics](/SECURITY_METRICS_REFERENCE.md) — and put the next exercise on the calendar before this one fades.

**Checkpoint:** A distributed AAR/IP in which every corrective action has a named owner and a due date, tracked items visible in your work system, and the next exercise scheduled.

**Watch out:** Findings without closure are theater. An improvement-plan item still open at the next annual tabletop is accepted risk in disguise — report it that way.

## What good looks like

- The session produced real findings — a tabletop that "went great" with nothing to fix tested a scenario you had already mastered, which was the wrong scenario.
- The hard questions got answered on the record: who declares, who decides on payment (and where OFAC screening happens), what the last-clean-copy decision looks like, and whether the out-of-band channel actually worked when Inject 6 landed.
- Module Three got its full time, and the recovery discussion used your real RTO/MTD numbers rather than adjectives.
- Every corrective action has an owner, a date, and a tracker entry; the sponsor has seen the AAR/IP; the plans that failed have been revised.
- The exercise recurs: this session is one tick in a standing cadence (an executive and a technical exercise each year), and findings from last time were verifiably closed before this one ran.

## Go deeper

**In this library:**

- [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md) — the exercise ladder (walkthrough to full failover), HSEEP alignment, governance, and resilience metrics this guide operationalizes
- [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md) — payment policy and OFAC exposure, backup architecture, exercising readiness, and the 90-day program the tabletop slots into
- [IR Playbooks](/IR_PLAYBOOKS.md) — the ransomware response playbook under test, escalation matrix, and regulatory notification deadlines
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) — the IR program structure the exercise validates
- [Active Directory Security](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) — what identity-down actually means, for scripting Module Three honestly
- [Security Metrics](/SECURITY_METRICS_REFERENCE.md) — reporting patterns for exercise cadence and finding-closure rates

**Authoritative external:**

- [CISA Tabletop Exercise Packages](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages) — the CTEP service page
- [CISA Cybersecurity Scenario CTEPs](https://www.cisa.gov/resources-tools/resources/cybersecurity-scenarios) — the situation-manual downloads, ransomware and sector variants
- [CTEP Package Documents](https://www.cisa.gov/resources-tools/resources/ctep-package-documents) — handbooks and templates, including the AAR-IP template
- [FEMA HSEEP](https://www.fema.gov/emergency-managers/national-preparedness/exercises/hseep) — the exercise doctrine (January 2020 revision) the CTEP process follows

---

*Guides are procedures, not doctrine — verify every command, download, and menu path against current official documentation before production use.*
