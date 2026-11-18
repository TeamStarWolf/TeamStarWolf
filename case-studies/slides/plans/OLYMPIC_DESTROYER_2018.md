# Slide plan: Olympic Destroyer 2018

- Study: case-studies/OLYMPIC_DESTROYER_2018.md
- Cover title: Olympic Destroyer / Forged Flags / Deadline Recovery
- Subtitle: Destructive malware hit the 2018 PyeongChang opening ceremony and salted its own forensics; attribution shifted for years afterward.
- Published: 18 November 2026
- Notes: The cover frames a destructive-wiper incident where planted indicators made early attribution wrong and recovery ran against a fixed public clock.

## CONTEXT | Why this case still teaches attribution
- Olympic Destroyer joins destructive malware, access across organizational boundaries, and a deception-laden attribution record.
- The historical attack struck the 2018 PyeongChang Winter Olympics during the opening-ceremony period.
- The public record built in stages: sample analysis in 2018, then a US indictment unsealed in October 2020.
- An indictment is an official allegation, not a conviction, and it does not reconstruct every victim system.
Caption: Evidence grade: Confirmed event, Reported attribution
Notes: The case matters because destructive effect, victim scope, and responsibility are separate propositions that early coverage tended to merge.

## TIMELINE | One clock, several kinds of evidence
Each row carries a different evidence weight, so no single confidence score fits the whole chronology.

| Date or period | Record and evidence type |
|---|---|
| Dec 2017 to Feb 2018 | Alleged preparation and intrusion, per indictment, not a measured dwell time |
| 9 February 2018 | Destructive deployment tied to the opening-ceremony period |
| 12 to 13 February 2018 | Talos publication and updates; key conclusions changed mid-analysis |
| 2018 research period | Code similarity, credential artifacts, and possible deception assessed |
| 19 October 2020 | US charges added a retrospective alleged operational account |
Caption: Evidence grade: Confirmed dates, Reported operational detail
Notes: Event dates, publication dates, and update dates are distinct, and a source strong on one can say little about another.

## FALSE FLAG | A forged fingerprint is not identity
- Kaspersky Rich-header analysis found similarities to Lazarus-associated material and assessed them as a false flag.
- A distinctive compiler-related artifact can itself be manipulated, so resemblance starts an explanation rather than ending it.
- Talos noted the embedded credential list changed as the malware harvested and recopied itself.
- A credential found inside a sample therefore need not have been planted before the first infection.
Caption: Evidence grade: Reported (researcher assessment)
Notes: The core defender lesson is that an attacker anticipating forensics will plant evidence, and shared code is a lead, not an authorship proof.

## EVIDENCE TIERS | Keep the three claim types apart
Left: Researcher assessment
- Talos associated destructive samples with the Games at moderate confidence.
- Recorded Future warned against treating small code overlaps as conclusive.
- Kaspersky supported a false-flag reading of the Rich-header similarity.
Right: Government allegation
- The October 2020 indictment alleges provider compromise and domain-admin access.
- It alleges deliberate imitation of Lazarus-associated malware.
- The charging announcement is an allegation and attribution, not an adjudicated verdict.
Caption: Evidence grade: Reported vs Inferred, held distinct
Notes: Researcher assessment, government indictment, and proven fact are three separate tiers, and a curated reference mapping aids navigation without validating the legal claims.

## DISCIPLINE | Phrases the house record prefers
- Replace "the malware proved who attacked" with sample analysis supported technical findings while attribution came separately.
- Replace "the indictment established guilt" with the indictment alleged the operation and the defendants' roles.
- Replace "the network was clean after restoration" with the named service returned under stated controls while investigation continued.
- Replace "no known indicator means no compromise" with no matching indicator was found within the stated telemetry and window.
Caption: Evidence grade: Demonstrated (method)
Notes: Exact wording carries the analytic confidence, so qualifiers survive into slides, diagrams, and PDFs rather than being trimmed for space.

## BOUNDARIES | Four trust lines worth separating
- Boundary A: a supplier workstation, support platform, and event enclave need distinct trust, not one reachable device.
- Boundary B: environmental knowledge like diagrams and runbooks aids an intruder even when it is not a credential.
- Boundary C: a valid credential proves a session, not that the action matches the owner's purpose.
- Boundary D: production authority and recovery authority must be defined independently.
Caption: Evidence grade: Demonstrated (proposed architecture)
Notes: These are proposed defensive boundaries prompted by the case, not descriptions of systems the research team inspected.

## SUPPLIER RISK | Inventory permissions, not company names
- Map which supplier personnel can take which actions, through which path, during which period.
- Record whether each access is personal, shared, delegated, or automated, and who approves and revokes it.
- Hold temporary event connectivity under an exception record with owner, scope, expiry, and tested replacement.
- Run a joint access review and a tabletop revocation of one named identity before the high-pressure window.
Caption: Evidence grade: Demonstrated (proposed control)
Notes: If supplier and customer describe a disabled support identity differently, the dependency is not yet understood.

## RECOVERY | A backup is readable, not proven trustworthy
- A backup can hold intact data while its management plane depends on the identity service under investigation.
- Separate three tests: data readability, application functionality, and controlled re-entry into service.
- Define recovery authority: who approves a restore, obtains keys, admits users, and can halt an unsafe one.
- A demonstration run with every production dependency available is not evidence for a combined-failure scenario.
Caption: Evidence grade: Demonstrated (proposed control)
Notes: Restoring files proves the first test only, so service restored and trust restored stay separate completion criteria.

## DETECTION | Build analytics as discriminating questions
- Design around a cluster of independent events: abnormal admin reach, unexpected remote execution, recovery changes, evidence removal.
- For each lead record observation, source, interpretation, competing explanation, and the next discriminating check.
- Keep a second worksheet for blind spots, where unknown is a status to manage, not a synonym for clean.
- Do not make every signal depend on telemetry from the system being damaged.
Caption: Evidence grade: Demonstrated (proposed method)
Notes: A correlation can raise concern without inventing causation, so the discriminating check is an authenticated change record, not a missing malware filename.

## COMMAND | First decisions under a fixed deadline
- Assign an incident commander with authority over both security and service delivery.
- Do not open by arguing a country name; containment can proceed from demonstrated harmful activity.
- Do not treat a broad shutdown as costless, since isolation can interrupt essential services.
- Record objective, side effects, owner, and reversal criteria for each significant decision.
Caption: Evidence grade: Demonstrated (proposed procedure)
Notes: Attribution may matter later, but a recorded rationale lets investigators tell an operational choice from unexplained missing evidence.

## GATES | Five checks before service is called clean
Left: Readiness and function
- Gate one: selected source, isolated destination, operator, evidence decision.
- Gate two: application works with intended data and dependencies.
- Gate three: only justified connectivity, with monitoring and rollback.
Right: Access and closure
- Gate four: relevant identities and sessions addressed within scope.
- Gate five: residual uncertainty, accepted risk, and follow-up owners recorded.
- A bypassed gate records who accepted the risk and when it is revisited.
Caption: Evidence grade: Demonstrated (proposed procedure)
Notes: The gates stop an urgent technical success from silently satisfying unrelated security claims, and a small team can run them as one checklist.

## EXPOSURE | Measure paths interrupted, not tickets closed
Stat: 30 | days to map one time-critical service
Stat: 60 | days to test separation and fallback
Stat: 90 | days to validate the whole response
- A path register records source, target, purpose, approval, time constraint, and interruption method.
- The scorecard states denominators and test dates rather than a selectively easy percentage.
Caption: Evidence grade: Demonstrated (proposed program)
Notes: Completion means owners agree on a path and have exercised its interruption decision, not that a diagram was attached to a ticket.

## CLOSING | Four questions a program must answer
- Which service matters now, stated in human terms rather than as a server name.
- Which access could endanger it, mapped as specific permissions and dependencies.
- How that access can be constrained and interrupted on demand.
- What evidence permits the service to return under stated controls.
Caption: Evidence grade: Demonstrated (author assessment)
Notes: The answers should survive loss of an ordinary workstation, a primary directory, a supplier contact, or an attractive attribution theory.
