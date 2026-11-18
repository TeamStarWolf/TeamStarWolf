# Slide plan: Dridex and the 2019 enforcement action

- Study: case-studies/DRIDEX_ENFORCEMENT_2019.md
- Cover title: Dridex / Evil Corp / The 2019 enforcement action
- Subtitle: How the December 2019 charges, sanctions and reward fit together, and why an indictment, a designation and a conviction are not the same thing.
- Published: 18 November 2026
- Notes: The cover frames the case as an attribution-and-disruption response, keeping charges, sanctions and technical outcomes as separate claim-types.

## OVERVIEW | What the December 2019 action actually combined
- The 5 December 2019 package joined a Pittsburgh indictment, OFAC sanctions, a reward offer and coordinated publicity.
- It was not an announcement that every Dridex infection was removed or that any named defendant was in custody.
- An indictment states allegations, a designation is an administrative action, and neither is a court conviction.
- Reading the record means separating what happened, what is alleged, what agencies assessed, and what was measured.
Caption: Evidence grade: Confirmed (official announcements issued); underlying charges Reported as allegations.
Notes: This slide sets the house rule that each claim-type carries its own standard of proof.

## OCTOBER 2015 | Disruption and arrest were separate events
- DOJ's 13 October 2015 announcement reported substantial disruption of the Bugat/Cridex/Dridex botnet and a nine-count indictment of Andrey Ghinkul.
- Ghinkul was arrested in Cyprus on 28 August 2015, with the United States seeking extradition.
- A civil injunction separately authorized redirecting infected machines' automated requests to substitute servers.
- The FBI's contemporaneous estimate was at least $10 million in direct domestic losses, a date-bound and US-bounded figure.
Caption: Evidence grade: Confirmed (DOJ announcement and civil filing); loss figure Reported as an FBI estimate.
Notes: Arrest, indictment and injunction reinforced one another without sharing scope or completion criteria.

## MEASUREMENT | Success and replacement in one filing
Stat: 3,469 | Addresses communicating on 15 October 2015
Stat: 1,267 | Addresses communicating on 9 December 2015
- The decline tracks the measured remediation effort, not a deduplicated global census of victims.
- The same filing acknowledged apparent new infrastructure built on a malware variant.
Caption: Evidence grade: Confirmed (figures stated in the court filing); eradication claims Inferred and left unresolved.
Notes: A December 2015 filing reported the targeted botnet neutralized while new infrastructure appeared, counted by unique IP to avoid researcher noise, and that caveat sits in the original record.

## SINKHOLE | Why the figures are not a global victim total
- The redirection count concerns communications reaching one substitute-server arrangement, distinct from the earlier British operation.
- "1,267 unique addresses in the measured effort" reflects the record better than "Dridex fell to 1,267 infections."
- A later report of continued activity does not falsify the earlier measured reduction; it may describe different infrastructure or windows.
- Preserving both the number and its collection boundary keeps the evidence honest.
Caption: Evidence grade: Inferred (analytical reading of the filing's stated scope).
Notes: The numerator means little without the boundary attached to how it was collected.

## PROSECUTION | One defendant moved through the full process
The timeline keeps a plea, a scheduled hearing and an actual disposition distinct, and separates a statutory maximum from a sentence.

| Date | Event |
| --- | --- |
| 28 Aug 2015 | Arrested in Cyprus |
| Feb 2016 | Extradited to the United States |
| 8 Feb 2017 | Pleaded guilty to conspiracy and computer damage |
| 6 Dec 2018 | Sentenced to time served |
Caption: Evidence grade: Confirmed (DOJ releases record the plea and sentence).
Notes: Ghinkul is the one adjudicated outcome, which is why the 2019 defendants keep allegation language.

## DECEMBER 2019 | Two criminal matters, not one combined case
Left: Pittsburgh indictment
- Charged Yakubets and Turashev over Bugat/Dridex conduct.
- Contained ten counts of alleged hacking and bank fraud.
- Expressly framed by DOJ as allegations.
Right: Nebraska complaint
- Connected Yakubets to the online name "aqua" in a separate Zeus scheme.
- A reward of up to $5 million was offered for information on his arrest or conviction.
- A reward is an investigative tool, not proof of capture.
Caption: Evidence grade: Confirmed (coordinated announcement); the two schemes' details Reported as allegations.
Notes: Merging the two malware names would quietly reassign victims and losses across unrelated matters.

## ATTRIBUTION | The alleged division of labor
Left: Yakubets (alleged)
- Oversaw development and distribution.
- Directed financial theft operations.
- Coordinated money-mule activity.
Right: Turashev (alleged)
- Handled administration.
- Ran an internal control panel.
- Managed botnet operations.
Caption: Evidence grade: Reported (role descriptions from the DOJ announcement, awaiting adjudication).
Notes: Group-level roles are broad allegations, not a transaction-by-transaction operational log.

## VICTIMS | Amounts attach to specific transactions
The charging document gives dated transactions and labels the school-district transfer an attempt, which the FBI narrative shortened to money wired out.

| Target | Alleged transaction |
| --- | --- |
| Sharon City School District | $999,000 transfer charged as an attempt (Dec 2011) |
| Penneco Oil | $2.16M and $1.35M transfers, plus a $76,520 attempt (2012) |
| 84 Lumber, Lesker, JWF | 2019 installations; ransomware alleged broadly |
Caption: Evidence grade: Reported (indictment allegations); the attempt-versus-loss gap Confirmed from source wording.
Notes: A charged attempt is not a verified net loss, and destination banks do not locate the operators.

## RANSOMWARE | Dated 2019 allegations, not proven payloads
- The indictment alleges installations at 84 Lumber (18 Feb), Kurt J. Lesker (4 Mar) and JWF Industries (19 Mar 2019).
- It also alleges broader ransomware activity across the campaign.
- Those statements do not establish a specific ransomware deployment, ransom demand or payment at each named organization.
- The record supports a shift toward broader intrusion consequences without making every later infection identical.
Caption: Evidence grade: Reported (general allegation); victim-specific outcomes left unresolved.
Notes: A general allegation and a particular proven count are different evidentiary objects.

## CAPABILITY | Why secure transport did not protect the endpoint
- The NCSC described Dridex on 5 December 2019 as a financial trojan delivered by malicious attachments and other malware such as Emotet.
- It said the malware could steal information during otherwise secure HTTPS browsing and support screenshots, file transfer and lateral movement.
- Protecting data in transit is separate from protecting a compromised endpoint that handles the data.
- This explains how a legitimate-looking banking session could be part of the attack, without naming the mechanism for every transfer.
Caption: Evidence grade: Reported (NCSC capability description); the endpoint distinction Inferred, not an encryption break.
Notes: Capability is kept distinct from confirmed loss at any specific victim.

## SANCTIONS | Treasury targeted a wider network
Stat: 17 | Individuals designated by Treasury
Stat: 7 | Entities designated, Evil Corp among them
Stat: $100M+ | Theft Treasury attributed to Dridex
Stat: 40+ | Countries in the alleged credential footprint
Caption: Evidence grade: Confirmed (designation issued); the FSB-tasking claim Reported as Treasury's assessment.
Notes: Treasury's 5 December 2019 designation addressed an organization and its support network as findings and assessments, and a sanctions designation is an administrative action, not another word for the indictment.

## UK ROLE | The British contribution and the stated effect
- The NCA said a dedicated team began investigating Dridex in 2014 and supplied material supporting the US charges and sanctions.
- Its December 2019 account reported eight money-laundering participants sentenced to more than forty years in aggregate.
- That aggregate belongs to the UK laundering defendants, not to Yakubets, Turashev or Ghinkul.
- The investigation connected technical inquiry with identification, finances and international coordination.
Caption: Evidence grade: Confirmed (NCA newsroom account of the coordinated operation).
Notes: Keeping each proceeding's defendants separate stops an impressive total from becoming a false claim.

## LOSS FIGURES | Different numbers are not one total
Stat: $220M | Attempted losses in the separate Zeus scheme
Stat: $70M | Actual losses DOJ stated for the Zeus scheme
Stat: $5M | Reward offered for information on Yakubets
Caption: Evidence grade: Reported (DOJ and Treasury releases, each with its own stated scope).
Notes: These figures describe different schemes, dates and harm categories, so the study declines to publish a combined total that no release supports.

## ADAPTATION | Later assessments are not retroactive 2019 facts
- Mandiant's 2 June 2022 research described UNC2165, overlapping with reported Evil Corp activity, shifting toward LockBit with high confidence it sought to evade sanctions.
- A shared ransomware service can be used by different actors, so a payload label alone does not resolve the organization.
- Treasury's 1 October 2024 trilateral designations alleged later assistance and work on "Dridex 2.0," showing continued enforcement.
- Those 2024 details were not publicly established in December 2019 and should not be written back into it.
Caption: Evidence grade: Reported (vendor and Treasury assessments); each bounded to its own window.
Notes: The record shows meaningful intermediate results and continued adaptation, not a single closing takedown.
