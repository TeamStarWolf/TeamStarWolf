# Produce and Operationalize an Intelligence Product

> By the end of this guide you will have taken one stakeholder's real question through the full intelligence cycle (from a written Priority Intelligence Requirement to a BLUF-first, TLP-marked finished product) and then operationalized it: handed graded indicators and ATT&CK-mapped behaviors to detection engineering, logged consumer feedback, and set the metric that proves the product changed a decision. Written for CTI analysts, SOC leads, and detection engineers who can reach their own telemetry and feeds and want to ship intelligence that *does something*, not a PDF that dies in an inbox.

| Time | Difficulty | You need | You'll produce |
|---|---|---|---|
| A few focused days for the first product end to end; the operationalization loop is ongoing | Intermediate: analytic tradecraft plus cross-team coordination | A named stakeholder with a real question, read access to your telemetry and feeds, a TIP (MISP or OpenCTI) or at minimum a structured doc, and a detection-engineering contact | A written, TLP-marked, BLUF-first product answering a PIR; a graded IOC/TTP package handed off as ATT&CK-mapped detections; a feedback record; and one program metric |

This guide operationalizes the intelligence cycle (Planning & Direction, Collection, Processing, Analysis, Dissemination, Feedback) described in the library's [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md). That reference is the doctrinal base: the cycle, STIX/TAXII, IOC enrichment, attribution methodology, and program metrics all live there in depth. The [threat-intelligence discipline path](/disciplines/threat-intelligence.md) is the learning track behind the tradecraft. This guide is the missing middle: the repeatable procedure that turns a question into a product and a product into deployed defense. It does not replace those documents; it sequences them for one turn of the loop.

## Before you start

- [ ] A named stakeholder and a real decision. Intelligence exists to inform a decision someone is about to make. If you cannot name the person and the choice, you are collecting, not producing; stop and find the consumer first.
- [ ] Read the CTI Fundamentals and Program Management sections of the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md); this guide assumes its vocabulary (the intelligence cycle, IOC vs TTP, the four intelligence tiers).
- [ ] A working analytic surface. A threat intelligence platform is ideal ([MISP](https://www.misp-project.org/) or [OpenCTI](https://www.opencti.io/)), but a disciplined analyst can run this loop once in a structured document. The platform matters more when you do it every week.
- [ ] Access to your own ground truth. Read access to the SIEM, EDR, and the feeds you already pay for. Your own telemetry is your highest-reliability source; treat external feeds as leads to confirm against it.
- [ ] A named detection-engineering counterpart. The operationalization half (Steps 6-8) is a handoff, and a handoff needs a receiver. Agree now who turns your findings into detections.
- [ ] Your sharing rules. Know your organization's [Traffic Light Protocol](https://www.first.org/tlp/) practice and any handling caveats before you write anything down; the marking is not an afterthought, it decides who may ever read the product.

## Step 1: Set the intelligence requirement (Planning & Direction)

A product with no requirement is a solution looking for a problem. Start by writing the question down as a Priority Intelligence Requirement (PIR): a specific, decision-linked, answerable question with a consumer and a deadline.

1. Interview the stakeholder, don't guess. "Tell me phishing" is not a requirement. "Which initial-access techniques are most likely to be used against our finance department in the next quarter, so we know where to spend the detection-engineering budget" is. Push every vague ask toward a decision it will inform.
2. Pin the tier, because it sets the audience, cadence, and format for everything downstream:
   - Strategic: informs executives and long-term resource allocation (risk, budget, posture).
   - Operational: tracks a campaign or actor's intent and targeting.
   - Tactical: the specific techniques, tools, and infrastructure a defender acts on.
   - Technical: the perishable indicators (IPs, domains, hashes) that go straight into controls.
3. Write the PIR in one sentence, plus its sub-questions and its success test: "this product succeeds if the stakeholder can decide X." Record who asked, what they decide, and when they need it.
4. File it as a tracked requirement, not a Slack message. In a TIP this is a formal requirement/RFI object; in a document it is a numbered row in a requirements register you can measure against in Step 8.

Checkpoint: A written PIR with a named consumer, a decision it feeds, an intelligence tier, and a due date, reviewable by the stakeholder before you spend a single collection hour.

Watch out: The most expensive CTI failure is producing an excellent answer to a question nobody asked. If you cannot connect the requirement to a decision, it is not a priority; send it back.

## Step 2: Plan collection against the requirement (Collection)

Now decide *where the answer could come from* before you go looking, so you collect against the PIR instead of drowning in feeds.

1. Build a collection plan: a simple matrix mapping each sub-question to the sources that could answer it, and to the gaps you cannot yet fill:

   | Sub-question | Internal source | External source | Gap / RFI |
   |---|---|---|---|
   | Which actors target our sector? | past IR cases, SIEM | ISAC bulletins, [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories), vendor reporting | premium actor tracking |
   | What TTPs do they use? | EDR telemetry | [ATT&CK group profiles](https://attack.mitre.org/groups/), [Threat Group Profiles](/THREAT_GROUP_PROFILES.md) | none |
   | What infrastructure is live now? | firewall/DNS logs | passive DNS, [urlscan.io](https://urlscan.io/), Shodan/Censys | dark-web access |

2. Lead with internal telemetry. What already happened in your environment outranks any external claim. Pull relevant history from the SIEM and past incidents first.
3. Layer external sources by type: OSINT and government advisories (free, high-signal), ISAC/ISAO sharing communities, commercial finished intelligence, and structured feeds. For automated feeds, poll a TAXII 2.1 server into your TIP rather than copy-pasting; the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md) covers STIX/TAXII ingestion, and [OSINT Reference](/OSINT_REFERENCE.md) covers pivoting techniques for the infrastructure questions.
4. Record source and TLP at the moment of collection. Where each datum came from and how you may share it are metadata you cannot reconstruct later; capture them now.
5. Decision point: collect or task? If a sub-question has no source, either accept the gap and caveat it in the product, or raise a Request for Information (RFI) to a peer, ISAC, or vendor. Naming the gap is itself a finding.

Checkpoint: A collection plan where every sub-question maps to at least one source or an explicit gap, and raw material is landing in your TIP or working folder with source and TLP attached.

Watch out: Collection without a plan becomes feed-hoarding (thousands of indicators, no answers). If a source does not map to a PIR sub-question, you do not need it for *this* product.

## Step 3: Process and grade what you collected (Processing)

Raw data is not intelligence. Normalize it, strip the noise, enrich it, and, critically, grade it, so the analysis in Step 4 weights each input by how much it deserves.

1. Normalize and deduplicate. Parse indicators into consistent types, merge duplicates, and run candidate IOCs against a known-good list: [MISP warninglists](https://github.com/MISP/misp-warninglists) flags CDNs, cloud ranges, and popular sites so you do not "discover" that `8.8.8.8` is in a feed.
2. Enrich each indicator once, from many sources. Aggregate enrichment through a tool like [IntelOwl](https://github.com/intelowl/IntelOwl) or [Cortex](https://github.com/TheHive-Project/Cortex) rather than pivoting site by site: reputation (VirusTotal), passive DNS, WHOIS age, and sandbox behavior in one pass. Keep hostile URLs and hashes defanged in notes (`hxxps://bad[.]example`).
3. Grade source reliability and information credibility with the Admiralty (NATO AJP-2.1) code, a two-character grade on every source and claim ([SANS: the Admiralty System for CTI](https://www.sans.org/blog/enhance-your-cyber-threat-intelligence-with-the-admiralty-system)):

   | Source reliability | | Information credibility | |
   |---|---|---|---|
   | A Completely reliable | D Not usually reliable | 1 Confirmed by other sources | 4 Doubtful |
   | B Usually reliable | E Unreliable | 2 Probably true | 5 Improbable |
   | C Fairly reliable | F Cannot be judged | 3 Possibly true | 6 Cannot be judged |

   A vendor blog you have verified before, corroborated by your own EDR, might be B2; an unattributed pastebin dump is F6 until something confirms it. Grade the *source* and the *content* independently; a reliable source can still relay an unconfirmed claim.
4. Decision point: carry or drop. Set a floor (for example, do not treat anything below a chosen reliability grade as more than a lead) and be explicit about single-source claims. Low-grade material can still go in the product, clearly labelled as such.

Checkpoint: A deduplicated, enriched, Admiralty-graded set of indicators and claims, each carrying its source and TLP, the evidence base analysis will reason over.

Watch out: Ungraded intelligence launders a rumor into a fact. The moment a claim loses its "usually reliable, probably true" caveat and becomes a flat assertion in a slide, you have manufactured false confidence.

## Step 4: Analyze with structured tradecraft (Analysis)

This is where data becomes judgment. Resist the pull to pattern-match to the actor you already suspect; use structure to make the reasoning explicit and challengeable.

1. Frame the intrusion with three complementary models: they answer different questions and you use all three:
   - [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html): *where in the sequence* is the activity (recon -> weaponization -> delivery -> exploitation -> installation -> C2 -> actions on objectives)? Good for spotting how early you can intervene.
   - [Diamond Model](https://www.threatintel.academy/diamond/): the four vertices *adversary, capability, infrastructure, victim* and the edges between them. This is your pivoting engine: a known C2 domain (infrastructure) links to a malware family (capability) links to other victims, expanding the picture from one indicator.
   - [MITRE ATT&CK](https://attack.mitre.org/): the shared vocabulary for *adversary behavior*. Map observed activity to techniques and sub-techniques; this is the mapping that carries straight into detection in Step 6, so it is not optional.
2. Run Analysis of Competing Hypotheses (ACH) for any attribution or "what is this" question. List the plausible hypotheses (always include a mundane one and "a different actor is mimicking X"), lay the graded evidence against each in a matrix, and look for evidence that disconfirms hypotheses rather than confirms your favorite. The hypothesis with the least disconfirming evidence wins; that discipline is what separates analysis from a hunch (see the structured-analytic-techniques material referenced in the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md)).
3. Build an ATT&CK Navigator layer as your working coverage artifact: the same file feeds the detection conversation in Step 6. Keep the format to the current Navigator schema:

   ```json
   {
     "name": "PIR-2026-014 — finance initial access",
     "domain": "enterprise-attack",
     "description": "Techniques assessed likely against Finance this quarter",
     "techniques": [
       { "techniqueID": "T1566.001", "score": 3, "comment": "Spearphishing Attachment — B2, seen in two peer reports" },
       { "techniqueID": "T1078",     "score": 2, "comment": "Valid Accounts — plausible, single-source" }
     ]
   }
   ```

   Pin the layer to the ATT&CK version you analyzed against (v19 is the current release as of 2026; record it, because technique IDs and tactics move between versions: Defense Evasion, for instance, split in v19). Confirm the layer-format field against the current [ATT&CK Navigator](https://github.com/mitre/attack-navigator) before importing.
4. State likelihood in calibrated estimative language, and keep it separate from confidence. Use the ODNI [ICD 203](https://www.intelligence.gov/assets/documents/intelligence-community-directives/ICD_203.pdf) yardstick so "likely" means the same thing to every reader:

   | Term | Probability | Term | Probability |
   |---|---|---|---|
   | Almost no chance | 01-05% | Likely / probable | 55-80% |
   | Very unlikely | 05-20% | Very likely | 80-95% |
   | Unlikely | 20-45% | Almost certain | 95-99% |
   | Roughly even chance | 45-55% | | |

   Then, separately, rate your analytic confidence (low / moderate / high) in the judgment based on evidence quality and source corroboration. ICD 203 is explicit that these are two different axes: a *high-confidence* judgment that something is *unlikely* is a perfectly coherent, useful statement; do not collapse them into one word.

Checkpoint: One or two key judgments, each expressed as a likelihood term plus a distinct confidence level, backed by an ACH matrix and an ATT&CK-mapped Navigator layer you can defend line by line.

Watch out: Mixing confidence and likelihood is the classic analytic error; "we're highly confident it's very likely" says less than it seems. And attribution is the trap: cluster activity to a named group only when the evidence survives ACH; "unattributed cluster" is an honest and often correct verdict.

## Step 5: Write the product BLUF-first for the audience (Dissemination)

The finished product exists to be *read fast and acted on*. Write for the consumer you named in Step 1, and put the answer first.

1. Lead with the BLUF: Bottom Line Up Front. The first two sentences state the judgment and the so-what: what you assess, how likely, your confidence, and what the reader should do or decide. Assume they read only that.
2. Match depth to tier. A strategic product for the CISO is the decision, the risk, and the recommendation; techniques go in an annex. A tactical/technical product for the SOC leads with the TTPs and the indicators. When both audiences need it, write one BLUF and layer a technical annex beneath it rather than two documents.
3. Structure the body predictably: BLUF -> key judgments (each with its estimative term and confidence) -> supporting analysis (the models and ACH reasoning from Step 4) -> indicators/TTP appendix -> sourcing and caveats. Consistency lets repeat readers navigate on autopilot.
4. Mark it with TLP 2.0 and carry sourcing. Apply the [FIRST TLP](https://www.first.org/tlp/) label the product's most restrictive input demands: `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, or `TLP:RED` (`TLP:CLEAR` replaced `TLP:WHITE`; `TLP:AMBER+STRICT` limits sharing to the recipient's own organization). State your sources and their Admiralty grades so a reader can weigh the judgment.
5. Show restraint on length. A one-page product that gets read beats a twenty-page report that gets skimmed. Every sentence should serve the consumer's decision.

Checkpoint: A finished product whose first paragraph answers the PIR in plain language, whose judgments carry calibrated likelihood and confidence, and whose TLP marking and sourcing are unambiguous, ready for the named consumer.

Watch out: Burying the lede kills the product. If the reader has to reach page three to learn what you think, the intelligence failed regardless of how good the analysis was. And never let a live malicious URL sit un-defanged in a document people will click.

## Step 6: Operationalize: hand off to detection engineering

This is the half most CTI programs skip, and it is where intelligence becomes defense. Convert the product's findings into things the SOC runs, deliberately preferring durable behaviors over perishable indicators.

1. Split the findings into IOCs and behaviors, and prioritize behaviors. Indicators (IPs, domains, hashes) are cheap to deploy but rot in days: the actor rotates infrastructure. Behaviors (ATT&CK techniques) are what the adversary must keep doing; a detection for the *technique* survives the actor changing domains. Climb the "pyramid of pain": IOC blocks first because they are free, technique detections next because they hurt the adversary.
2. Route the IOCs into controls with an expiry. Push graded indicators from the TIP to the SIEM watchlist, firewall, and DNS/email gateways, but set a review or expiration date so a stale block does not become permanent invisible risk. The [SIEM Reference](/SIEM_REFERENCE.md) covers ingestion; watchlist hygiene matters as much as the block.
3. Turn behaviors into detections with your engineering counterpart. Each prioritized technique becomes a candidate Sigma rule, audited and tuned before it pages anyone; that full procedure is [Build and Deploy Your First Detection](/guides/BUILD_YOUR_FIRST_DETECTION.md), and the doctrine is the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md). Hand over the technique ID, the observable behavior, and any sample telemetry; check the [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) for logic that may already exist.
4. Package the handoff as structured data, not prose. A STIX 2.1 bundle linking indicators to the attack patterns they belong to makes the handoff machine-ingestible and unambiguous:

   ```python
   # Illustrative only — confirm object shapes against the current
   # OASIS cti-python-stix2 docs (https://github.com/oasis-open/cti-python-stix2)
   from stix2 import Indicator, AttackPattern, Relationship

   ap = AttackPattern(
       name="Spearphishing Attachment",
       external_references=[{"source_name": "mitre-attack", "external_id": "T1566.001"}],
   )
   ind = Indicator(
       name="Staging domain observed in finance-targeted lure",
       pattern="[domain-name:value = 'bad.example']",   # defanged in prose; literal in the machine object
       pattern_type="stix",
   )
   rel = Relationship(ind, "indicates", ap)
   ```

5. Drive the coverage conversation with the Navigator layer from Step 4. Overlay "techniques this actor uses" against "techniques we detect" to produce a ranked gap list; that is exactly [Run an ATT&CK Coverage Gap Assessment](/guides/RUN_A_COVERAGE_GAP_ASSESSMENT.md), and the prioritization logic (detect what real adversaries actually do first) is the [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md).
6. Feed the other consumers too. Behavioral findings seed a hunt ([Hunt for Living-off-the-Land Activity](/guides/HUNT_FOR_LOTL_ACTIVITY.md)); exploitation intelligence re-ranks patching ([Triage a New CVE](/guides/TRIAGE_A_CVE.md)); active-incident context accelerates response ([Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)).

Checkpoint: Every actionable finding has a destination (IOCs in controls with expiry dates, prioritized techniques accepted into the detection-engineering backlog with technique IDs, and a ranked coverage-gap list), not a product that ends at "here is what we found."

Watch out: A wall of raw IOCs dumped on the SOC with no context or grades is not operationalization; it is noise transfer, and it trains the SOC to ignore you. Hand off behaviors and graded, contextualized indicators, and prefer the detection that outlives the infrastructure.

## Step 7: Disseminate, share, and track feedback (Feedback)

Delivery is not the end of the loop; the feedback that closes it is what makes the next product better and proves this one mattered.

1. Deliver through the right channel within the TLP bounds you set in Step 5: the exec briefing, the SOC channel, the ticketing system, wherever the consumer actually works.
2. Share outward where it helps and the marking allows. Contribute indicators and finished analysis to your ISAC/ISAO or sharing community via MISP or a TAXII feed, strictly inside the product's TLP label: `TLP:AMBER+STRICT` never leaves your organization; `TLP:CLEAR` can help the whole community.
3. Collect consumer feedback deliberately. Ask the named stakeholder three questions: Did this answer your question? Did it change what you did? What do you still need? Log the answers against the PIR; silent delivery teaches you nothing.
4. Decision point: does feedback spawn a new requirement? New questions and gaps become new PIRs, and the loop returns to Step 1. A healthy CTI function is measured partly by how much of its work is pulled by consumer feedback rather than pushed by feeds.

Checkpoint: The product reached the consumer through a channel they use, any outward sharing respected the TLP marking, and written feedback is recorded against the PIR, including any follow-on requirements.

Watch out: Fire-and-forget dissemination is how CTI teams end up guessing what stakeholders want. If you never ask whether the product changed a decision, you cannot claim it did, and you cannot improve.

## Step 8: Measure whether it changed anything

One product is an anecdote; a measured program is a case for its own existence. Track outcomes, not activity.

1. Measure the loop, not the feed. Useful measures include: PIR/RFI turnaround time, share of standing PIRs satisfied on cadence, detections shipped from products, true-positive detections traceable back to a specific product, and decisions the consumer confirms your intelligence informed. The program-metrics section of the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md) and the [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) go deeper.
2. Retire vanity metrics. "Indicators ingested" and "reports published" measure motion, not effect; a program can double both while informing zero decisions. Report outcome metrics to leadership and keep volume metrics for internal capacity planning only.
3. Feed the numbers back into direction. If tactical products get consumed and strategic ones get ignored, that is a Step 1 signal about where your requirements should concentrate next quarter.

Checkpoint: At least one outcome metric recorded for this product (a detection shipped, a decision influenced, a gap closed) and a place to trend it as you run the loop again.

Watch out: Counting outputs feels productive and proves nothing. The number that matters is how often intelligence changed a defender's action; if you cannot point to one, the honest finding is that the loop is not yet closed.

## What good looks like

- Every product starts from a written PIR tied to a named consumer and a real decision; nothing is produced "because it's interesting."
- Sources and claims are Admiralty-graded, and judgments use calibrated estimative language with confidence stated separately; a reader knows exactly how much weight each line carries.
- The analysis is structured and challengeable: ACH ruled out the alternatives, and Kill Chain / Diamond / ATT&CK each did a distinct job rather than being name-dropped.
- The product is BLUF-first, audience-matched, and TLP-marked, and it gets read in minutes.
- The findings are operationalized: behaviors became ATT&CK-mapped detections, indicators went to controls with expiry dates, and the coverage gap is on someone's backlog with an owner.
- Feedback is logged and a real outcome metric exists: the loop closes, and the next requirement is pulled by a consumer, not pushed by a feed.

## Go deeper

In this library:

- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md): the doctrinal base: the intelligence cycle, STIX/TAXII, IOC enrichment, attribution, TLP, and program metrics this guide sequences.
- [threat-intelligence discipline path](/disciplines/threat-intelligence.md): the learning track, tooling, and certifications behind the tradecraft used here.
- [Threat Group Profiles](/THREAT_GROUP_PROFILES.md): actor TTPs and campaign context for the attribution and targeting questions in Steps 2 and 4.
- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md): prioritizing which techniques deserve detection first, by real adversary prevalence.
- [Build and Deploy Your First Detection](/guides/BUILD_YOUR_FIRST_DETECTION.md): the receiving procedure for the Step 6 handoff: behaviors into tuned Sigma rules.
- [Run an ATT&CK Coverage Gap Assessment](/guides/RUN_A_COVERAGE_GAP_ASSESSMENT.md): turning the Navigator layer into a ranked, owned gap list.
- [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) & [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md): detection doctrine and ready-to-adapt logic per technique.
- [detection-engineering discipline path](/disciplines/detection-engineering.md): the counterpart discipline that consumes your product.
- [OSINT Reference](/OSINT_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md): the collection, hunting, and response consumers of finished intelligence.

External:

- [ODNI ICD 203: Analytic Standards](https://www.intelligence.gov/assets/documents/intelligence-community-directives/ICD_203.pdf): the estimative-probability yardstick and the confidence-vs-likelihood discipline.
- [FIRST: Traffic Light Protocol 2.0](https://www.first.org/tlp/): the current TLP labels and handling rules for marking and sharing.
- [The Diamond Model of Intrusion Analysis](https://www.threatintel.academy/diamond/): the adversary/capability/infrastructure/victim model and its pivoting logic.
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html): the original intrusion-sequence framework.
- [MITRE ATT&CK](https://attack.mitre.org/) and the [ATT&CK for CTI training](https://attack.mitre.org/resources/training/cti/): the behavior vocabulary that carries into detection, and the free course on using it.
- [SANS: Enhance Your CTI with the Admiralty System](https://www.sans.org/blog/enhance-your-cyber-threat-intelligence-with-the-admiralty-system): practical source-and-information grading for CTI.
- [OASIS cti-python-stix2](https://github.com/oasis-open/cti-python-stix2): the reference library for producing the STIX 2.1 handoff bundle.

*Guides are procedures, not gospel. Verify every command, flag, tool name, and framework version against current official documentation before relying on it in production; doctrine, TLP, ATT&CK versions, and tooling all change.*

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
