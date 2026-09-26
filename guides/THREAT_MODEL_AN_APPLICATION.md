# Threat Model an Application

> **By the end of this guide you will have a data flow diagram, a ranked STRIDE threat list, mitigations mapped to each finding, an honest ATT&CK coverage layer, and backlog items your team can actually ship.** This is for developers, security champions, and security engineers running their first (or first *rigorous*) threat model on a real application — no prior threat modeling experience required.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 3–4 hours (first pass, one application) | Intermediate | An architecture you can describe, OWASP Threat Dragon, a backlog (Jira/GitHub Issues), ideally one developer + one security person | DFD, ranked threat list with IDs, mitigation map, ATT&CK Navigator layer, security stories in the backlog, a written re-model trigger |

## Before you start

- [ ] Read the STRIDE and DFD sections of the library's [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) — this guide operationalizes that doctrine and assumes its vocabulary (elements, trust boundaries, STRIDE-per-element).
- [ ] Have the inputs on hand: an architecture diagram (even a whiteboard photo), API specs, and a list of what data the system holds. The full input list is in the "Inputs and Outputs" section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md).
- [ ] Get [OWASP Threat Dragon](https://www.threatdragon.com/) — use the web app to learn, or install the desktop app from the [official releases page](https://github.com/owasp/threat-dragon/releases/latest) for real work. Windows-only teams can alternatively use the [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) (free, [click-to-download](https://aka.ms/threatmodelingtool)).
- [ ] Bookmark the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for Step 7 — no install needed, it runs client-side in your browser.
- [ ] Book the people: the developer who knows the code and someone who thinks like an attacker. Solo modeling works but misses more.

## Step 1 — Scope the system and name what you're protecting

Write a scope statement before you draw anything. One paragraph: what the system does, which deployment you're modeling (prod, not the demo stack), and what's explicitly out of scope.

Then list the assets an attacker would actually want, ranked: customer PII, credentials and session tokens, payment data, admin functions, the CI/CD pipeline itself. This is the "crown jewels" identification from PASTA Stage 1 in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) — you're borrowing it even though this walkthrough is STRIDE-driven, because ranking in Step 5 is impossible without knowing what a breach costs.

Record your assumptions ("TLS terminates at the load balancer", "the database is not internet-reachable"). Every assumption is a claim you'll verify or a finding waiting to happen.

**Checkpoint:** A scope paragraph, a ranked asset list, and 3–5 written assumptions. If you can't say what the worst-case breach is, you're not ready to diagram.

**Watch out:** Scoping "the whole platform" on a first pass. Model one application and its direct dependencies. You can widen scope on the next iteration — the re-model trigger in Step 8 exists for exactly this.

## Step 2 — Set up Threat Dragon and create the model

1. Open [threatdragon.com](https://www.threatdragon.com/) and click **Login to Local Session** to try the tool with a sample model, or launch the installed desktop app.
2. Create a new threat model. Fill in the title, owner, and description from your Step 1 scope statement.
3. Add a diagram and select **STRIDE** as the diagram type — this sets the threat categories offered in Step 4 (Threat Dragon 2.x also supports LINDDUN, CIA, CIA-DIE, and PLOT4ai; if your system processes personal data, plan a second LINDDUN pass — see the LINDDUN section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md)).

**Checkpoint:** An empty STRIDE diagram is open in the editor with your model's metadata filled in.

**Watch out:** The web demo's local session lives in your browser. For a model your team will keep, use the desktop app and save the model file into the application's own repository — that's "threat model as code" and it's what makes Step 8's freshness check possible.

## Step 3 — Draw the DFD with trust boundaries

Build a Level 1 DFD — the whole system decomposed into its major parts, per the DFD levels table in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md). Drag from the stencil:

- **Actor** (rectangle) for each external entity: the user's browser, a partner API, the payment gateway.
- **Process** (circle) for each thing that runs your logic: web API, auth service, background worker.
- **Store** (two parallel lines) for each place data rests: PostgreSQL, S3 bucket, Redis, log store.
- **Data flow** (arrow) for every movement of data. Name each flow after the data on it ("credentials", "order JSON"), not the technology. On each flow's properties, set the **Protocol** and tick **Encrypted** and **Public Network** where true.
- **Trust boundary** (box or curve) at every point trust changes: internet → DMZ, app → database, user → admin, app → third-party API, CI/CD → production. The common-boundaries table in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) is your checklist.

Mark anything you drew but won't analyze as **Out of Scope** in its properties and fill in **Reason for out of scope**. Save the model from the toolbar.

**Checkpoint:** Every arrow is named after data, every property set, and every arrow that crosses a dashed line crosses a *named* trust boundary. A colleague who's never seen the system can narrate a request's path through the diagram.

**Watch out:** Two classic failures — modeling at code level (a DFD is not a class diagram; 6–12 processes is plenty) and forgetting the boring flows: logging, backups, monitoring agents, and the CI/CD deploy path. Those flows carry credentials and they're where repudiation and supply-chain findings live.

## Step 4 — Enumerate threats element by element with STRIDE

Work the diagram systematically, not by inspiration. The STRIDE-per-element table in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) tells you which categories apply to which element type — processes take all six; data flows take Tampering, Information Disclosure, and Denial of Service; external entities take Spoofing and Repudiation; stores take T, R, I, and D.

For each in-scope element, in priority order (trust-boundary crossings first):

1. Select the element and click **New Threat** at the lower right of the diagram editor. Fill in **Title** and **Threat Type** (both required), a **Description** of the attack and impact, and leave **Status** as Open.
2. Then run the generators so you don't stop at the threats you already knew: **New Threat by Type** walks you through each STRIDE category for the element ( **Previous** / **Next** to cycle, **Apply** to keep one), and **New Threat by Context** suggests threats keyed off the properties you set in Step 3 — a flow's Protocol/Encrypted/Public Network, an actor's Provides Authentication, a store's Stores Credentials. Its suggestions are drawn from the [OWASP Automated Threats](https://owasp.org/www-project-automated-threats-to-web-applications/) (OATs) catalog, so treat them as a bot-and-abuse supplement to your STRIDE sweep, not a substitute for it.
3. For every boundary-crossing flow, ask the six questions from the "Applying STRIDE to DFD Trust Boundary Crossings" section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md): who could fake the source, modify the data, deny the interaction, read it, disrupt it, or gain privilege through it?

Give every threat a stable ID (TM-001, TM-002…) in its title. Findings without IDs die in meetings.

**Checkpoint:** Every in-scope element has been swept; the threat count is roughly 3–6 per boundary crossing. Worked examples of what good findings look like: the REST API STRIDE table in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md).

**Watch out:** Category blindness. If your finished list has zero Repudiation or zero Denial of Service entries, that's almost never because none exist — it's a blind spot (the quality-metrics section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) tracks exactly this). Also note Threat Dragon's generators don't produce threats *for* trust boundaries themselves — boundaries shape which elements are interesting; the threats attach to elements and flows.

## Step 5 — Rank the threats

For each threat, set **Severity** in the threat dialog — the choices are TBD / Low / Medium / High / Critical; leave nothing at TBD — driven by likelihood × impact against the asset list from Step 1. Impact comes from what the asset is worth; likelihood from how exposed the element is (internet-facing and pre-auth beats internal and post-auth).

When two threats feel identical in severity and you need a tiebreak, score them with DREAD (Damage, Reproducibility, Exploitability, Affected users, Discoverability, 1–3 each) — the scoring rubric and its known limits are in the DREAD section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md). Put the number in the **Score** field.

Set threats you're consciously not pursuing to **N/A** with the reasoning in the mitigation field — silence and a decision look identical six months later unless you write the decision down.

**Checkpoint:** Every threat has a Severity; the top 5 are ones you can defend out loud to the team. Expect a rough pyramid — a handful of High/Critical, more Medium, most Low.

**Watch out:** Don't burn an hour calibrating scores. DREAD is subjective by design; what matters is *relative* order within this model so the backlog gets worked top-down. If everything is Critical, nothing is.

## Step 6 — Map each threat to a mitigation

Work down the ranked list. For each threat, write into the **Mitigations** field a control that is *specific enough to build*: name the mechanism and where it lives. "Validate the `alg` header server-side and sign with RS256" is a mitigation; "improve JWT security" is a wish.

Pull from the Secure Design Principles (Mitigations Catalog) section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) — it maps authentication, data protection, input validation, defense-in-depth, and auditability controls to the STRIDE categories they defeat. For control *classes* (harden / detect / isolate / deceive / evict), cross-check [D3FEND_REFERENCE.md](/D3FEND_REFERENCE.md); for the broader control-framework picture, [CONTROLS_MAPPING.md](/CONTROLS_MAPPING.md) and [ENTERPRISE_SECURITY_CONTROLS.md](/ENTERPRISE_SECURITY_CONTROLS.md).

Update each threat's **Status** as decisions land: Mitigated, Accepted, Transferred, Avoided, or Eliminated.

**Checkpoint:** Every High and Critical threat has a named, buildable mitigation — or an explicit Accepted status with a named owner. No High/Critical row says "TBD".

**Watch out:** One mitigation is often a single point of failure. For your top threats, stack a preventive control *and* a detective one (the defense-in-depth table in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) is the pattern) — the detection side is where [DETECTION_RULES_REFERENCE.md](/DETECTION_RULES_REFERENCE.md) earns its keep.

## Step 7 — Map to ATT&CK where the mapping is honest

Not every design flaw maps to an ATT&CK technique, and forcing it corrupts your coverage picture. The honest rule: map a threat only when it describes an operational technique an adversary executes, not a missing property of your design. From the cloud threats table in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md): SSRF to the instance metadata service is T1552.005; a public storage bucket is T1530; container escape is T1611. A missing authorization check on an admin endpoint, by contrast, has no clean technique ID — record it as a design finding and move on. The STRIDE-to-tactic column in the reference is orientation, not citation.

For the threats that do map:

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose **Create New Layer**, and pick the matrix that matches your stack (Enterprise, or its cloud/container platform views).
2. Annotate each mapped technique with a score and color for control coverage — red for no control, yellow for partial, green for mitigated, per the layer workflow in the MITRE ATT&CK Integration section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md). Add the TM-ID in the technique comment.
3. Export the layer as JSON and commit it next to the threat model file. Navigator runs client-side, so the export *is* the record.

For technique context while you work, keep [ATTACK_TECHNIQUE_ATLAS.md](/ATTACK_TECHNIQUE_ATLAS.md) and [ATTACK_MITIGATIONS_REFERENCE.md](/ATTACK_MITIGATIONS_REFERENCE.md) open alongside.

**Checkpoint:** A Navigator layer JSON exists in the repo; every colored cell traces back to a TM-ID; and at least some of your findings are honestly *not* on the layer.

**Watch out:** A mostly-green layer built from forced mappings is worse than no layer — it tells leadership the app is covered when the real risk lives in the unmappable design findings. Count both kinds in your report.

## Step 8 — Land the findings in the backlog and set the re-model trigger

A threat model that lives in a tool nobody reopens is shelfware. Convert it:

1. For each Open High/Critical threat, create a backlog item titled with the TM-ID, containing the threat description, the mitigation as the acceptance criterion, and a link to the model file. That's the security-story pattern from the sprint-level workflow in [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md).
2. For Accepted threats, get the acceptance from someone entitled to accept it — the product owner or asset owner, by name, in writing (risk register or the ticket itself).
3. Commit the Threat Dragon model JSON and the Navigator layer to the application's repository so model changes ride code review — the CI freshness-check pattern in the SDLC section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) can then fail a PR that changes architecture without touching the model.
4. Write the re-model trigger into the team's working agreement, straight from the review-cadence table: new externally-facing feature or third-party integration → sprint-level model of the delta; architecture change or security incident → update the full model; and an annual refresh regardless.

**Checkpoint:** Backlog items exist and are scheduled, the model and layer are in version control, and the team can say out loud what event forces the next threat modeling session.

**Watch out:** The trigger is the step teams skip, and it's the one that keeps the model alive. A threat model reflects the system on the day it was drawn — "we did threat modeling" (past tense, once) is how a two-year-old DFD ends up justifying current architecture decisions.

## What good looks like

- Every trust boundary crossing on the DFD has at least one threat recorded against it — or a written reason it doesn't.
- All six STRIDE categories appear in the threat list, or the gap is explained; category counts aren't lopsided by blind spot.
- Every High/Critical threat has a buildable mitigation, an owner, and a backlog link; every Accepted risk has a named accepter.
- ATT&CK mappings are defensible one by one, and design findings that don't map are reported alongside the layer, not hidden by it.
- The model file and Navigator layer are in the application's repo, and the re-model trigger is written down where the team plans work.
- The real test arrives later: when the next pentest report lands, most findings should already be in your threat list. That overlap metric — from the outcome-metrics section of [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) — is how you know the model works.

## Go deeper

**In this library:**

- [THREAT_MODELING_REFERENCE.md](/THREAT_MODELING_REFERENCE.md) — the doctrinal base for this guide: STRIDE, PASTA, LINDDUN, attack trees, DREAD, DFDs, tools, metrics, SDLC integration.
- [D3FEND_REFERENCE.md](/D3FEND_REFERENCE.md) — defensive countermeasure classes to pair with each ATT&CK-mapped finding.
- [ATTACK_MITIGATIONS_REFERENCE.md](/ATTACK_MITIGATIONS_REFERENCE.md) — MITRE's M-code mitigations for the techniques on your Navigator layer.
- [SECURITY_ARCHITECTURE_REFERENCE.md](/SECURITY_ARCHITECTURE_REFERENCE.md) — the design patterns your mitigations should land in.
- [SECURE_CODING_REFERENCE.md](/SECURE_CODING_REFERENCE.md) — implementation-level guidance for the input-validation and authz findings.
- [THREAT_INFORMED_DEFENSE_REFERENCE.md](/THREAT_INFORMED_DEFENSE_REFERENCE.md) — where the coverage layer from Step 7 fits in a wider threat-informed program.

**External:**

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) — compact process reference built around the Four Question Framework.
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/) — the values and principles behind every methodology choice in this guide.
- [Threat Dragon documentation](https://www.threatdragon.com/docs/) — current official docs for every UI action in Steps 2–6.
- [Microsoft Threat Modeling Tool docs](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started) — the equivalent walkthrough if your team standardizes on Microsoft's tool.

---

*Guides are procedures: tool UIs and commands change, so verify each step against the current official documentation before relying on it in production.*
