# Slide plan: Zerologon 2020: Patch, Enforcement and the Exception Boundary

- Study: case-studies/ZEROLOGON_2020.md
- Cover title: Zerologon 2020 / Phased Enforcement / The Exception Boundary
- Subtitle: CVE-2020-1472 shows why an installed update, an enforced policy and verified remediation are distinct, and why exceptions must expire.
- Published: 18 November 2026
- Notes: The cover sets the frame: a vulnerability and deployment study, with phased enforcement as the house angle.

## EXECUTIVE SUMMARY | A vulnerability and deployment study, not a victim count

- Zerologon, CVE-2020-1472, shows a security update can be urgent while its full deployment still needs careful dependency work.
- The vulnerability threatened Active Directory domain controllers, a central source of enterprise authority.
- Primary records support malicious use in 2020 but give no worldwide victim total or single attacker identity.
- A deployment is incomplete if it updates software while losing track of accounts still allowed weaker behavior.
Caption: Evidence grade: Confirmed vulnerability; malicious use Reported, no victim total.
Notes: Executive-assessment framing; sources are [1] through [7], and no live network was examined or changed.

## KEY FACTS | One CVE, two phases, seven primary records

Stat: 7 | Primary records in scope
Stat: Aug 11 | 2020 patch phase begins
Stat: Sep 16 | 2020 CERT/CC note VU#490028
Stat: Feb 9 | 2021 enforcement by default
- CVE-2020-1472 is the Netlogon secure-channel vulnerability known as Zerologon.
- The seven records are Microsoft's deployment guidance and enforcement reminder, a Microsoft activity account, CERT/CC's note and three CISA bulletins.
- The August 2020 update gave immediate protection; enforcement by default arrived with the February 9, 2021 update.
Caption: Evidence grade: Confirmed, dated vendor and government records.
Notes: Dates and record set from [1][2][3]; CISA and Microsoft publication channels per [4][5][7].

## PART 1 | Patched, enforced and verified are three claims

- A vulnerability is a potential failure; an exploit demonstration is a method that worked under stated conditions.
- An incident is actual use against a target; exploitable in theory is not exploited in the wild.
- Keep "patch available", "patch deployed" and "verified remediated" as separate facts with separate evidence.
- A severity score rates potential, not demonstrated impact in a specific environment.
Caption: Evidence grade: Confirmed distinctions; remediation urgency differs from incident confirmation.
Notes: Evidence-level discipline from [1][2]; dated-confidence progression later shown in [4][5].

## PART 1 | A reused IV in AES-CFB8, not a defeat of AES

- CERT/CC's VU#490028 identifies reuse of a zero-value initialization vector in AES-CFB8 within MS-NRPC.
- The flaw can let an unauthenticated attacker impersonate a domain-joined computer, including a domain controller.
- The issue is unsafe use of a cryptographic construction, not a general mathematical defeat of AES.
- "Unauthenticated" means no prior authenticated session is required, not that every controller is internet-reachable.
Caption: Evidence grade: Confirmed (CERT/CC VU#490028); no exploit method reproduced.
Notes: Cryptographic description and the unauthenticated caveat from [1]; kept at a safe conceptual level by design.

## PART 1 | A domain controller is authority, not one host

- A domain controller holds identity authority that other systems rely on for their trust decisions.
- Compromise of that authority can affect trust across systems, not just one ordinary workstation.
- This does not mean every possible downstream action happened in every observed attack.
- Suspected identity-infrastructure compromise needs an incident-response workstream beside the deployment one.
Caption: Evidence grade: Inferred scope guidance drawn from the record.
Notes: Authority-scope reasoning from [1]; the two-workstream recommendation is original analysis.

## PART 2 | What the August 11 patch actually changed

- Microsoft's August 11, 2020 phase required updates on all applicable controllers, including read-only ones.
- It enforced secure RPC for Windows machine accounts, trusts and controllers, keeping compatibility handling for other devices.
- Events 5827/5828 mark denials, 5830/5831 exception allowances and 5829 initially permitted vulnerable connections.
- "Patch installed" is too broad; name which controllers, accounts, incompatible devices and exceptions apply.
Caption: Evidence grade: Confirmed Microsoft guidance; events alone do not prove exploitation.
Notes: Phase scope and event categories from [2]; the closure-statement point is original analysis.

## PART 2 | February enforcement and the exception boundary

- Microsoft's January 14, 2021 reminder set the February 9 update to enable domain-controller enforcement by default.
- The enforcement update superseded the earlier FullSecureChannelProtection registry choice.
- Explicit exceptions still permitted vulnerable connections and retained risk.
- A release date does not patch an offline or unmaintained system; exposure did not end automatically on February 9.
Caption: Evidence grade: Confirmed; enforcement distinct from exception removal.
Notes: Enforcement-by-default and the superseded registry choice from [3][2]; calendar caveat is original analysis.

## PART 2 | Assumed exploitation became reported awareness

CISA's statements changed confidence level by date; the quotations are not interchangeable.

| Date | CISA statement | What it established |
|---|---|---|
| Sep 18, 2020 | Emergency Directive 20-04 | Assumed active exploitation |
| Sep 24, 2020 | Netlogon follow-up | Aware of active exploitation |
| Oct 9, 2020 | AA20-283A, with FBI | Access, not altered data |
Caption: Evidence grade: Confirmed dated statements; confidence preserved per date.
Notes: Assumption then awareness from [4][5]; the elections-support qualification from [6].

## PART 2 | Observed chains and the limits of attribution

- CISA's October 9, 2020 advisory, with FBI input, reported APT actors chaining older flaws with CVE-2020-1472.
- It noted unauthorized access to some elections support systems, with no evidence of altered elections-data integrity.
- Microsoft's November 30 account described a rise in alerts from September 13, mixing authorized red-team and real attackers.
- Alert volume is not a count of distinct confirmed breaches; the study assigns no single attacker or victim total.
Caption: Evidence grade: Reported activity; attribution and totals left open.
Notes: Chaining and access-not-modification from [6]; alert rise and mixed population from [7].

## DEFENDER VIEW | Separate four kinds of deployment proof

- First, prove update applicability by matching product and role to vendor guidance, not a generic assumption.
- Second, prove installation on the actual controller, confirming resulting version and operational health.
- Third, prove effective policy: which accounts receive default enforcement and which remain permitted by exception.
- Fourth, prove business compatibility through representative workflows, using approved non-destructive validation.
Caption: Evidence grade: Original defensive recommendation.
Notes: Four proofs and non-destructive validation condensed from [2]; original recommendation.

## DEFENDER VIEW | Manage exceptions as expiring decisions

- Record each exception's dependency, owner, justification, affected account, compensating restrictions and resolution.
- "Legacy device" is too weak; explain why it cannot comply and the evidence for a replacement or update path.
- Set an expiry tied to a real action, not an arbitrary date repeatedly extended without review.
- A dashboard should read "deployed with named exceptions", never "fully remediated" while allowances remain.
Caption: Evidence grade: Original recommendation; an exception is part of the configuration.
Notes: Exception register and communication boundary from [2]; original recommendation.

## CROSS-CUTTING THEMES | What this case overstates versus understates

Left: Easy to overstate
- "Patched" read as enforced, or enforced read as every exception removed.
- An assumption of exploitation read as confirmed victim evidence.
- Access to a supporting system read as proven data modification.
Right: Easy to understate
- The August patch gave material protection and should not have been deferred.
- The February enforcement phase required active compatibility work.
- Malicious use in 2020 is supported even without a victim total.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated pairs rest on [2][5][6][7]; keep phases and confidence levels distinct.

## CLOSE | A traceable account beats patch or panic

- A security update can be urgent while its complete deployment still requires careful dependency work.
- Patched does not mean enforcing, and enforcing does not mean every exception removed.
- Connect software state, effective policy, dependency ownership and evidence of actual compromise.
- Maintain a complete inventory, time-limit exceptions and keep incident recovery separate from patch completion.
Caption: Evidence grade: case-specific conclusions.
Notes: Conclusion synthesis across [1] through [7]; durable practices stated as original operational lessons.
