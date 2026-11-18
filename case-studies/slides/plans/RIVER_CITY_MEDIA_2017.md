# Slide plan: River City Media 2017

- Study: case-studies/RIVER_CITY_MEDIA_2017.md
- Cover title: River City Media 2017 / An Open Backup / 1.4 Billion Records
- Subtitle: How a spam operation exposed its own files through a passwordless backup, and why the record count is not a count of people.
- Published: 18 November 2026
- Notes: The cover frames a misconfiguration exposure and sets up the record-count versus unique-person discipline that runs through the deck.

## SCOPE | What this case is, and is not
- A public disclosure, a cataloged dataset, a company denial, and litigation that ended in a stipulated dismissal.
- The public sources do not make every allegation on either side a finding of fact.
- The acquisition evidence and a definitive merits ruling on the access mechanism were not retrieved.
- Three distinctions hold: records versus unique addresses, a proposed technique versus a deployed one, and jurisdiction versus merits.
Caption: Evidence grade: Confirmed
Notes: This slide sets the bounds so later chronology is not read as a resolved verdict.

## DISCOVERY | A researcher finds files with no password
Left: Researcher account (6 March 2017)
- Chris Vickery wrote that a collaboration with CSOOnline and Spamhaus began in January.
- He reported encountering publicly exposed files that lacked a password.
- He characterized the collection as River City Media operational material and a mailing dataset.
Right: Independent catalog (Have I Been Pwned)
- The entry dates the exposure to January 2017, added to the service on 8 March.
- Names, physical addresses and IP addresses are among the listed data categories.
- Passwords are not among the listed compromised categories.
Caption: Evidence grade: Reported (researcher account), Confirmed (catalog entry)
Notes: The two columns separate a participant's published account from an independent dataset catalog.

## NUMBERS | Records are not unique people
Stat: 1.4B | records in the exposed mailing dataset
Stat: 393M | unique email addresses after dedup
Stat: 0 | passwords in the listed compromised data
- Repeated appearances of one address raise the row count without adding a person.
- Neither number is a census of unique individuals.
- The smaller figure is a different measurement, not proof the collection was small.
Caption: Evidence grade: Confirmed
Notes: Deduplication materially changed the published measure, so the units must stay visible.

## MISCONFIGURATION | An exposure, not an intrusion
Left: Open-backup reading
- The researcher said the exposed files responded without a password.
- The cause is framed as the operator's own backup configuration, not a customer service.
- An attacker's operational-security failure exposed its own operational material.
Right: Intrusion counter-allegation
- The 9 March company release denied that backups were left on an open server.
- The later complaint alleged unauthorized access rather than open exposure.
- The acquisition mechanism stays the central contested question.
Caption: Evidence grade: Reported (both sides), Inferred (access mechanism)
Notes: Keeping a misconfiguration exposure distinct from a hack is the house discipline for this case.

## REBUTTAL | The company's specific denial
- The 9 March release was distributed through a newswire, not an independent investigation.
- It said a document called Project X1 came from an unaffiliated applicant, not a company method.
- It denied a separate technique described in chat material and defended third-party data licensing.
- A company press release states claims; it does not settle them.
Caption: Evidence grade: Reported
Notes: The denial names precise disputes about acquisition, inference and characterization rather than a blanket objection.

## EVIDENCE | Possession is not deployment
- A document in a repository shows the repository held it, given sound authenticity and custody.
- It does not show the business approved, executed or successfully used the contents.
- Calling something an outside proposal does not by itself prove it was never implemented.
- Resolving one dispute does not automatically resolve the others.
Caption: Evidence grade: Inferred
Notes: The deck reproduces no mailing-abuse mechanism or operational scripts, which are unnecessary to the dispute.

## LAWSUIT | River City Media goes to court
The operator and individual plaintiffs filed suit in federal court in Washington State.

| Field | Detail |
| --- | --- |
| Filing date | 21 March 2017 |
| Court | Eastern District of Washington |
| Case number | 2:17-cv-00105-SAB |
| Defendants | Kromtech, Chris Vickery, media companies, a reporter |
Caption: Evidence grade: Confirmed
Notes: The docket maps the filings and parties; it is not itself a verdict on the incident.

## JURISDICTION | A procedural order, not a verdict
- The 28 August 2017 order addressed personal jurisdiction, not the underlying merits.
- It found sufficient grounds over the individual researchers and reporters discussed.
- Several dismissal motions were denied with leave to renew, and the reporter's motion was denied.
- Allegations recited inside an order are not final adjudicated technical findings.
Caption: Evidence grade: Confirmed (order), Reported (allegations)
Notes: A judicial paragraph can read as more authoritative than the complaint the allegation came from.

## 2018 | A narrower order and a policy debate
Left: Partial order (9 April 2018)
- Dismissed International Data Group with prejudice.
- Recorded CXO Media's agreement to submit to personal jurisdiction.
- Vacated an earlier jurisdictional discovery order as moot, not the whole action.
Right: Expert statement (10 April 2018)
- Hosted by the Center for Democracy and Technology.
- Cited the case as litigation that can threaten security research.
- Policy advocacy, not a judicial conclusion about authorization here.
Caption: Evidence grade: Confirmed (order), Reported (advocacy)
Notes: One column is a narrow procedural step; the other is a broader debate about deterring disclosure.

## DISPOSITION | How the federal case ended
- An 31 August 2018 stipulation dismissed all plaintiffs' claims against all defendants with prejudice.
- Each party agreed to bear its own costs and attorney fees.
- On 4 September, the judge accepted the stipulation and ordered the file closed.
- The retrieved documents disclose no payment amount and no merits admission.
Caption: Evidence grade: Confirmed
Notes: The primary stipulation and order were read directly rather than through a later secondary account.

## OUTCOME | A dismissal is not a verdict
- A stipulated dismissal can end litigation without establishing disputed allegations.
- No damages award, conviction or approved technical reconstruction attaches to the dismissal.
- The word "settlement" overstates what the primary documents support.
- The concrete facts are the stipulation, the dismissal with prejudice, and the closure order.
Caption: Evidence grade: Confirmed
Notes: The endpoint should not be rewritten as either side winning a factual verdict.

## PRIVACY | Exposed people may not know the collector
- The subjects form an aggregated contact collection, not customers of a familiar service.
- A person can appear in the data with no obvious account relationship to manage the exposure.
- The exposed list is other people's harvested data, not the operator's own information.
- This study outputs no leaked records, addresses or emails for any individual.
Caption: Evidence grade: Inferred
Notes: The harvested-data context is why responsible handling matters more than the headline scale.

## LESSONS | What to carry forward
- Keep a misconfiguration exposure distinct from a hack or an intrusion.
- Keep gross record counts distinct from unique addresses and from real reachable people.
- Preserve provenance: how material was obtained and which observations were reproduced.
- Describe what each legal event actually did instead of labeling a winner or loser.
Caption: Evidence grade: Confirmed
Notes: These four habits keep an account of contested security research fair and traceable.
