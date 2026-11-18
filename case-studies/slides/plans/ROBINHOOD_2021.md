# Slide plan: Robinhood 2021 support-desk breach

- Study: case-studies/ROBINHOOD_2021.md
- Cover title: Robinhood 2021 / Support-desk vishing / Tiered data exposure
- Subtitle: A phone caller talked a support employee into remote control of a company endpoint, reaching customer data across distinct exposure tiers.
- Published: 18 November 2026
- Notes: The cover frames the incident as a social-engineering and access-control case, not a software exploit.

## VECTOR | A phone call, not an exploit
- An outsider called a customer-support employee and claimed an internal role, citing a supervisor name and a nonpublic system name.
- The employee installed a remote-control tool on the company laptop and allowed control of a session that already held internal access.
- The SEC describes the caller posing as IT; the Massachusetts order describes human resources, and both pretexts stay source-dependent.
- The endpoint reached confidential front-end systems; the trading application itself was not the breached component.
Caption: Evidence grade: Confirmed (enforcement orders); pretext role Reported (differs by source)
Notes: Keeping the vector precise prevents the case from being mistold as a code vulnerability.

## TIMELINE | Warning, recurrence, disclosure
A documented June near-miss preceded the November breach and two later disclosures.

| Date | Event |
|---|---|
| Jun 14, 2021 | Remote-access session obtained on an employee computer |
| Jun 28, 2021 | Corrective action names remote-tool prevention and detection |
| Nov 3, 2021 | Support employee vished; about four hours of remote access |
| Nov 8, 2021 | Public disclosure; extortion demand noted after containment |
| Nov 16, 2021 | Update adds several thousand phone-number entries |
Caption: Evidence grade: Confirmed (SEC order, company notices)
Notes: Separating event dates from disclosure dates stops later detail from being read back into the first announcement.

## GAP | The June lesson that did not generalize
Left: What was blocked
- The known digital signature of the tool used in June was blocked among other actions.
- An incident report around June 28 named remote-desktop tooling as a corrective action.
Right: What stayed open
- Unapproved remote-access software broadly was not blocked until after November 3.
- The November session used a different version of the same software, defeating the signature-only fix.
Caption: Evidence grade: Confirmed (SEC Release 34-102170)
Notes: The central failure was fixing the last observed artifact rather than the underlying access capability.

## TIERS | Exposure was bounded and uneven
Stat: 5M | email addresses exposed, one group
Stat: 2M | full names exposed, a separate group
Stat: 310 | people with name, date of birth, ZIP
Stat: 10 | customers with more account detail
- Robinhood believed Social Security, bank-account and card numbers were not exposed.
- A count of list entries is not automatically a count of unique people.
Caption: Evidence grade: Confirmed (SEC order figures; non-exposure Reported by company)
Notes: The honest headline is tiered contact-data exposure, not millions of hacked trading accounts.

## POPULATIONS | Separate labels, not one number
These groups carry different sensitivity and should not be flattened together.

| Population | Robinhood figure |
|---|---|
| Email addresses | About 5 million people |
| Full names | About 2 million, a different group |
| Name, date of birth, ZIP | About 310 people |
| Extensive account detail | About 10 customers |
| Massachusetts addresses in file | At least 117,763 individuals |
Caption: Evidence grade: Confirmed (SEC and Massachusetts orders)
Notes: The Massachusetts order states the name, email and phone fields did not appear together as associated records.

## EVIDENCE | Downloaded, visible, merely reachable
- A bulk file was obtained and downloaded, giving a strong record count with uncertain deduplication.
- Some internal-system information was reachable but not downloaded, a different evidentiary state.
- Other records the outsider may have seen on screen carry uncertain viewing scope and duration.
- A forensic scope matrix should pair each data category with its specific evidence of access.
Caption: Evidence grade: Confirmed (Massachusetts order distinctions)
Notes: Absence of a download event is not proof that a record was never viewed.

## BRIDGE | One session, many systems
- Controlling an already authenticated endpoint let the attacker reach business tools without logging in to each service directly.
- Strong login authentication does not stop someone operating a device after a legitimate user has signed in.
- The employee left the device unattended during part of the event while remote access continued.
- Sensitive actions such as bulk export or recovery changes warrant fresh verification inside an existing session.
Caption: Evidence grade: Confirmed (session access); session controls Inferred (proposed)
Notes: The endpoint and its live session, not a database admin account, were the route into customer data.

## REPORTING | Alarm raised, route hard to reach
- The employee struggled to find a reporting phone number and tried a general contact line at 11:13 and 11:20 p.m.
- An ethics hotline reached an automated service; a relative also searched for a workable contact route.
- A security ticket was opened at 12:52 a.m. with a callback at 12:55 a.m., after the 11:33 p.m. reboot.
- The reporting process existed in principle but was difficult to use under time pressure.
Caption: Evidence grade: Confirmed (Massachusetts order timeline)
Notes: The first alerting attempts began before the reboot, so the timeline should not be retold as all-after.

## CONTAINMENT | Demand after access, loss unproven
- The contemporaneous notice said the intrusion was contained and an extortion demand followed.
- Robinhood stated it believed the incident caused no customer financial loss.
- The notices do not establish that any extortion payment was made or that systems were encrypted.
- Contact-data exposure still raises phishing and pretext risk without direct theft from an account.
Caption: Evidence grade: Reported (dated company representations)
Notes: Data exposure is kept distinct from account compromise and from any funds movement.

## PENALTIES | Settlement-wide, not breach-only
Stat: $7.5M | Massachusetts settlement-wide fine
Stat: $45M | SEC combined civil penalties
Stat: $1M | per entity for Reg S-P and S-ID
- The SEC total splits into $33.5M for one entity and $11.5M for the other.
- Both resolutions covered unrelated securities matters, so neither figure is a breach-only cost.
Caption: Evidence grade: Confirmed (consent order and SEC order amounts)
Notes: Adding the fines and labeling the sum the breach cost would misallocate unrelated findings.

## POSTURE | What the record does and does not show
Left: What the record shows
- Social engineering of a support employee and about four hours of remote endpoint control.
- Tiered contact-data exposure and a later extortion demand after containment.
Right: What it does not establish
- That affected people had trading accounts taken over or funds stolen.
- A complete forensic timeline, an exfiltration inventory, or any extortion payment.
Caption: Evidence grade: Inferred (bounded reading of the orders)
Notes: Affected people could include applicants who never became customers, so protection follows the data.

## DEFENSE | Separate help from bulk extraction
- Grant support roles enough to resolve a single customer issue without unrestricted exports covering millions.
- Require a business purpose, scoped fields, bounded population and logged approval for bulk exports.
- Route remote assistance through an approved channel with controlled enrollment and session visibility.
- Gate sensitive export or reveal actions behind verification an outsider controlling the screen cannot satisfy.
Caption: Evidence grade: Demonstrated (proposed controls)
Notes: Ordinary support tools become dangerous only when an unverified caller can operate a privileged endpoint.

## VERIFY | Test the property, not the ticket
- Baseline the support device groups, the remote tools they can run and the apps reachable from them.
- Authorized test of installation restrictions and session detection using harmless tools and synthetic data.
- Data-access test confirming a support role can work but cannot pull an unjustified bulk file.
- After-hours reporting test measuring time to human acknowledgment and to a containment decision.
Caption: Evidence grade: Demonstrated (verification method)
Notes: A blocked historical signature is not enough to close a broader promise about unapproved remote access.

## JUDGMENT | A near miss that stayed dangerous
- The strongest lesson is the interaction between a known risk and an incomplete fix.
- A plausible call opened the path, but broader restrictions, narrower access and usable reporting could each have reduced the loss.
- None of those controls depends on assuming every employee will always recognize deception.
- The measure of improvement is whether the next comparable attempt is prevented, limited or rapidly contained.
Caption: Evidence grade: Inferred (defensible synthesis)
Notes: The case is best taught as an access-control and response-design study grounded in a documented social-engineering incident.
