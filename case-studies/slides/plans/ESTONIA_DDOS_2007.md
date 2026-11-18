# Slide plan: Estonia 2007, DDoS and the Limits of a Cyber-War Story

- Study: case-studies/ESTONIA_DDOS_2007.md
- Cover title: Estonia 2007 / DDoS and resilience / The attribution line
- Subtitle: Weeks of denial-of-service against Estonian government, bank and media services, and why the cyber-war label stays a contested frame.
- Published: 18 November 2026
- Notes: The cover sets the case as the canonical nation-scale DDoS while flagging that state direction was never conclusively proven.

## EXECUTIVE | The significant case that was not a national shutdown
- Interference with public-facing services became a national coordination problem and drew international assistance.
- Contemporary records show differentiated access by service, time and user location, not a country switched off.
- The study separates recorded service effects from policy responses, and an analyst's hypothesis from proven attribution.
- It claims no complete traffic records and offers no total economic-loss figure.
Caption: Evidence grade: Confirmed from contemporary records; Inferred for the significance framing.
Notes: Set the honest baseline before any slide reaches for the dramatic retelling.

## APRIL 29 | What the CERT Estonia statement actually said
- Domestic internet traffic continued and users could reach foreign websites.
- Access from abroad to government pages was restricted as a defensive measure.
- Most public-sector pages were again reachable domestically while overseas restrictions continued.
- A foreign journalist blocked and a domestic resident served could both describe the same page accurately.
Caption: Evidence grade: Confirmed (CERT Estonia statement, preserved by the Estonian government).
Notes: The primary statement dismantles the claim that Estonia's whole internet went dark.

## SCOPE | A campaign label, not one uniform event
- Ottis's analysis framed the activity around the dispute over relocating a Soviet-era monument in Tallinn.
- It bounded the main attack period as April 27 to May 18 across public and private targets.
- Predominantly denial-of-service against web, email, DNS and routing, with some intrusion attempts noted.
- Political context explains significance; it does not license treating a user's language or nationality as evidence.
Caption: Evidence grade: Reported (Ottis 2008 analysis, qualitative by its own account).
Notes: Grouping related activity for study is not proof of one command structure behind every outage.

## TIMELINE | Dates that should not be forced to agree
The primary record carries dated milestones that answer different questions.

| Date or period | Source record | Reading boundary |
|---|---|---|
| Apr 27-May 18 2007 | Ottis campaign period | Research framing, not proof hostile activity stopped |
| April 29 2007 | CERT Estonia statement | Domestic vs overseas reachability distinction |
| May 23 2007 | NATO briefing | Assistance and continuing attacks described |
| June 14 2007 | NATO ministerial | Call for urgent protective work |
| July 5 2007 | Estonian action plan | Approved future work, not proof of implementation |
| May 14 2008 | Centre documents signed | Distinct from later accreditation |
Caption: Evidence grade: Confirmed dates from primary sources; Inferred where the records differ.
Notes: Ottis ends the window May 18 while NATO's May 23 briefing reports continuing attacks, and the difference is kept, not smoothed.

## NUMBERS | What is traceable, and what is not
Stat: 22 | days in Ottis's main campaign window
Stat: 2004 | year the Tallinn centre was proposed
Stat: 2008 | year that centre was established
- The sources carry no complete national dataset of failed transactions or service-hours lost.
- No total outage percentage or monetary damage figure is assigned.
Caption: Evidence grade: Confirmed (Ottis 2008; CCDCOE history); national totals unsupported.
Notes: Every figure traces to a source, and the missing national total is stated rather than invented.

## AVAILABILITY | DDoS is a service problem, not a breach
- A denial-of-service event blocks legitimate use by exhausting a path, connection capacity, application resource or supporting service.
- A homepage loading does not prove a payment or administrative submission works.
- Availability is separate from integrity and confidentiality; disruption alone does not prove theft or tampering.
- Defenders should still run a proportionate check for a simultaneous intrusion without claiming an unseen breach.
Caption: Evidence grade: Inferred (original defensive analysis).
Notes: Name the bottleneck and the user journey instead of reading one failed probe as a national verdict.

## FILTERING | Restored needs a population attached
Left: What the control protects
- Restricting overseas access can preserve capacity for domestic users.
- Emergency restrictions need an owner, objective, review interval and removal criteria.
- Test restoration from multiple locations and through representative tasks.
Right: What the control costs
- Legitimate people outside the country are left unable to obtain information.
- Geography is a coarse proxy for intent; a blocked source can be a proxy or compromised device.
- Aggregate success can hide a critical failure at the edge of the population.
Caption: Evidence grade: Confirmed effect (CERT statement); Inferred for the guidance.
Notes: The correct report describes the protected function and the remaining exclusion together.

## ATTRIBUTION | What the record can and cannot conclude
- Ottis argued a Russian information-operation reading was plausible, and explicitly said the analysis did not prove one.
- NATO's May 23 spokesman stressed tracing difficulty and declined to name an origin.
- Separate the traffic source, infrastructure owner, operator, organizer and any sponsor; they need not overlap.
- An address is not a person, and a pattern consistent with a hypothesis is not proof alternatives were eliminated.
Caption: Evidence grade: Reported hypothesis with its caveat; not Confirmed state attribution.
Notes: A patriotic-hacktivist surge or rented botnet is not the same as a proven state operation.

## ALLIANCE | Assistance was not an Article 5 invocation
- Estonia requested political solidarity and technical assistance and received both.
- NATO sent an expert and other nations provided assistance.
- Asked directly, the spokesman said Estonia had not requested Article 5.
- The June 14 ministerial recorded agreement that urgent protective work was needed.
Caption: Evidence grade: Confirmed (NATO briefing and ministerial news, 2007).
Notes: Support and solidarity are a narrower, firmer claim than treating the event as a declared armed attack.

## ACTION PLAN | A government can cope and still find work to do
- The July 5 announcement said normal daily activities were not paralyzed and the response was regarded as adequate.
- It still called for stronger emergency preparation, a cyber-defence strategy and legal work.
- It distinguished the spring's availability focus from future threats to confidentiality and data integrity.
- Adopted policy is not demonstrated capability; every action needs a named owner, a resource decision and a test.
Caption: Evidence grade: Confirmed (RIA action-plan announcement, July 5 2007).
Notes: Resilience is preserving important functions and recovering with honest limits, not the absence of every failure.

## CCDCOE | The centre's history began before the attack
- Seven nations and Allied Command Transformation signed the Tallinn centre's establishment documents in May 2008.
- The centre concept was proposed in 2004 and approved in 2006, with accreditation later in 2008.
- It describes itself as a member-funded research, training and exercise institution, not an operational command.
- The attacks added urgency, but the centre was neither invented from nothing nor the unit that defended Estonia in 2007.
Caption: Evidence grade: Confirmed (CCDCOE history; NATO May 2008 release).
Notes: Institutional chronology guards against a satisfying but incorrect origin story.

## MEASUREMENT | No invented national outage total
- The sources give no consistent national dataset, so no outage percentage or monetary figure is calculated.
- A measurement scheme should define the service, population, time interval, observation method and failure criterion.
- Separate attack-induced failure, deliberate defensive restriction and unrelated operational fault.
- Record uncertainty in the numerator and the denominator; repeated attempts are not unique users.
Caption: Evidence grade: Inferred (defensive analysis); national dataset absent from the record.
Notes: A number with an unclear denominator does not make a national event more rigorous.

## MATRIX | Useful evidence against the unsupported shortcut
The decision matrix pairs each question with evidence that holds and a shortcut that does not.

| Question | Useful evidence | Unsupported shortcut |
|---|---|---|
| What is unavailable? | Representative tasks, internal and external reachability | One failed probe means the country is offline |
| Who is excluded? | Population-specific tests and restriction records | Domestic recovery means universal recovery |
| Who was responsible? | Qualified evidence at each attribution layer | Source address proves state direction |
| What did partners do? | Confirmed assistance, authority and action records | Political solidarity equals treaty invocation |
| What changed afterward? | Adoption records and later implementation tests | A plan proves completed capability |
Caption: Evidence grade: Inferred (defensive framework drawn from the record).
Notes: The matrix improves precision without forcing a team to solve attribution before it protects users.

## LESSONS | Disciplined resilience over a simple story
- Protect essential functions and describe the exclusions that remain.
- Keep attribution separate from immediate defence, and keep disruption separate from an act of war.
- Test whether adopted policy becomes operational capability, with owners and rehearsed restoration.
- A precise account of partial disruption and coordinated recovery teaches more than a country vanishing from the internet.
Caption: Evidence grade: Inferred (synthesis of the primary record).
Notes: Separate the measured impact from the mythologized retelling and the case keeps its weight without exaggeration.
