# Slide plan: Mirai and Dyn 2016

- Study: case-studies/MIRAI_DYN_2016.md
- Cover title: Default credentials / One DNS provider / Availability risk
- Subtitle: How a botnet of unmanaged IoT devices drove a DDoS against DNS provider Dyn and left dependent sites unreachable on 21 October 2016.
- Published: 18 November 2026
- Notes: The cover frames a case where the people who can prevent device recruitment are rarely the people who suffer the downstream outage.

## CONTEXT | What happened on 21 October 2016
- A DDoS driven by Mirai-infected devices struck DNS provider Dyn, degrading name resolution for many dependent sites.
- Access to major services such as Twitter, Reddit and Spotify became intermittent for hours across affected regions.
- A later plea account describes the attack as intended to disrupt a gaming network, with Dyn and its customers caught in the effect.
- The incident is an availability event at shared infrastructure, not a breach of the downstream sites it disrupted.
Caption: Evidence grade: Confirmed (official legal account and public reporting)
Notes: This slide fixes the single dated anchor before any mechanism or number is introduced.

## MECHANISM | How Mirai recruited devices
- Mirai scanned the Internet for embedded devices exposed over telnet and similar remote-access services.
- It logged in using common default credentials that owners had never changed, enslaving cameras, recorders and routers.
- Recruitment relied on weak factory passwords at ecosystem scale, not on a novel software exploit.
- The research retrospective observed a peak near 600,000 infections across its measurement window.
Caption: Evidence grade: Reported (named research team describing its own measurements)
Notes: The takeover mechanism is default-credential access, which must stay distinct from the flood it later produced.

## EFFECT | From botnet mechanism to DNS outage
- The enslaved devices were directed to flood Dyn with traffic, overwhelming name-resolution capacity.
- When DNS answers failed, users could not reach sites that depended on Dyn even though those sites' own servers were healthy.
- Device recruitment and the DDoS effect are two separate investigations with two separate owners.
- An ecosystem infection peak is not the count of devices attacking one target at one moment.
Caption: Evidence grade: Inferred (operational model built from bounded public sources)
Notes: Keeping the recruitment cause apart from the outage effect prevents the common collapse into one story.

## DISTINCTION | Unreachable is not the same as breached
Left: Availability impact (what occurred)
- Name resolution through Dyn failed or slowed for affected users.
- Dependent sites became intermittent or unreachable for hours.
- The harm was loss of access, measured by failed customer journeys.
Right: Compromise (what the sources do not establish)
- No evidence that the disrupted sites were themselves breached.
- No data theft or code execution on those downstream services is claimed.
- A green application dashboard can coexist with a failed dependency.
Caption: Evidence grade: Confirmed (availability) and Unknown (downstream compromise)
Notes: Treating an outage as a breach misdirects the response and overstates what the evidence supports.

## MEASUREMENT | Numbers that resist false precision
Each headline figure measures a different population and clock, and none substitutes for another.

| Metric | What it actually measures | Grade |
|---|---|---|
| Observed IP addresses | An observation key, not a physical device count | Inferred |
| Infection estimate | Ecosystem size across a research window | Reported |
| Traffic rate | Bandwidth within a sampling interval | Reported |
| Financial loss | One named company's net-revenue estimate | Reported |
Caption: Evidence grade: Reported and Inferred (populations and clocks differ)
Notes: Giving each number an explicit unit keeps an address count from becoming a device total.

## SCALE | Figures anchored to named sources
Stat: 600,000 | Peak Mirai infections, 2016-2017 research
Stat: 620 Gbps | Revised rate of the September Krebs attack
Stat: $2.7M | Sony estimated net-revenue loss, DOJ 2020
Stat: 21 Oct | Date of the Dyn-related disruption
- Each value stays attached to its source and scope, not combined into a single worldwide total.
- The oft-cited higher attack magnitude is a reported estimate, not a precise measured universal.
Caption: Evidence grade: Reported (provider, research and company estimates)
Notes: Figures without their provenance invite exactly the false precision the study warns against.

## CHRONOLOGY | A timeline that invents nothing
The dated record runs from a September precursor to the convictions years later.

| Date | Supported milestone | Grade |
|---|---|---|
| 20-21 Sep 2016 | Krebs attack, rate revised to about 620 Gbps | Reported |
| 21 Oct 2016 | Dyn-related disruption, dependent sites intermittent | Confirmed |
| Sep 2018 | DOJ sentences the original Mirai authors | Confirmed |
| 9 Dec 2020 | DOJ announces the Dyn-related guilty plea | Confirmed |
Caption: Evidence grade: Confirmed and Reported (legal milestones with one estimate)
Notes: An announcement date is not an attack date, and the table keeps the two apart.

## ATTRIBUTION | Rare legally established attribution
- Unlike many state-linked cases, this one has attribution anchored in court: guilty pleas, not inference.
- A December 2020 plea covered a Mirai variant used in the 21 October attacks that affected Dyn.
- A September 2018 case sentenced Paras Jha, Josiah White and Dalton Norman for the original Mirai botnet.
- The convictions establish responsibility that forensic telemetry alone could not.
Caption: Evidence grade: Confirmed (official legal announcements)
Notes: Legally established attribution is what makes this case unusually solid ground for teaching.

## LINEAGE | A public release is not one actor
- The Mirai source code was released publicly in 2016, letting many operators run their own variants.
- The original-authors case and the later Dyn-related plea describe different defendants.
- Shared malware lineage cannot prove that every related attack has the same operator.
- Collapsing distinct proceedings into one actor merely because both say Mirai is an attribution error.
Caption: Evidence grade: Confirmed (distinct legal proceedings)
Notes: A released codebase spawns copycats, so a common mechanism is evidence of reuse, not of one hand.

## CONCENTRATION | One provider, many dependent sites
- Many prominent services resolved through a single DNS provider, so one disruption cascaded widely.
- The unit of availability is the customer's intended operation, not any one team's healthy server.
- A clean vulnerability scan of your own servers does not answer whether you survive a dependency you do not control.
- Name resolution, identity and external APIs can each decide whether a transaction completes.
Caption: Evidence grade: Inferred (dependency model drawn from the incident)
Notes: Infrastructure concentration is the structural lesson that outlives the specific 2016 malware.

## DEFENSE | Two linked but distinct programs
Left: Stop your assets becoming attack infrastructure
- Give each connected device an accountable owner with budget and authority.
- Change defaults, segment to real dependencies and track support end dates.
- Verify a fix closes the exposure, not just that a reboot quieted a graph.
Right: Tolerate failures outside your control
- Follow a customer journey through every external dependency.
- Prove continuity options with an exercised, controlled failure test.
- Treat a second vendor as a hypothesis until a journey survives the loss.
Caption: Evidence grade: Inferred (proposed practice, author's interpretation)
Notes: Neither program excuses the other, and both are needed to address this case honestly.

## PROCUREMENT | Buying devices you can maintain
- Specify identity: a way to tell a physical asset from its current network address.
- Require recovery without a shared permanent supplier password.
- Make the supplier demonstrate discovering, obtaining and confirming a software update.
- Define the exit: data removal, sanitization evidence and what happens when support ends.
Caption: Evidence grade: Demonstrated (proposed acceptance exercise with artifacts)
Notes: A device that checks image quality but cannot be maintained becomes tomorrow's recruited node.

## RESILIENCE | DNS diversity must be exercised
- A second provider does not establish failover until a controlled dependency-loss test proves it.
- A proposal must name who maintains records, how credentials are protected and how changes propagate.
- Stale records or an untested emergency procedure can turn a backup into a new outage.
- The acceptance criterion is an observed customer journey, not two contracts on paper.
Caption: Evidence grade: Demonstrated (exercise-based acceptance criterion)
Notes: Redundancy claimed but never rehearsed is the failure mode this lesson is built to catch.

## TAKEAWAYS | What to carry into your own program
- Keep the botnet mechanism, the DDoS effect and downstream availability as three separate questions.
- Keep unreachable distinct from breached, and every number attached to its source and clock.
- Treat legally established attribution here as the exception, and shared malware as reuse rather than one actor.
- Run one small, non-disruptive exercise over one device population and one customer journey.
Caption: Evidence grade: Inferred (synthesis of bounded sources and proposed practice)
Notes: The closing ask is a verifiable demonstration, which beats any unqualified claim of protection against Mirai.
