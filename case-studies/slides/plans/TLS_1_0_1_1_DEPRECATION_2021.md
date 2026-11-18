# Slide plan: Retiring TLS 1.0 and 1.1: A Standard, Not a Switch

- Study: case-studies/TLS_1_0_1_1_DEPRECATION_2021.md
- Cover title: Retiring TLS 1.0 and 1.1 / March 2021 / Standard, not switch
- Subtitle: A formal deprecation and browser removals were a policy milestone, not an instant universal shutdown; legacy clients and intranets could persist.
- Published: 18 November 2026
- Notes: Reference study of a standard change, not an incident; no live server tested and no exploit code run.

## EXECUTIVE SUMMARY | A standards decision was not a universal shutoff

- RFC 8996 in March 2021 formally deprecated TLS 1.0 and 1.1, along with DTLS 1.0.
- It prohibited negotiating and falling back to the old versions; it was not evidence that every service stopped accepting them that month.
- Several vendors announced coordinated retirement in 2018, then revised schedules or split disablement from removal.
- Compressing this into "TLS 1.0 ended in 2021" misstates both the technology and the operational history.
Caption: Evidence grade: Confirmed RFC and dated vendor record.
Notes: Executive framing from [1]; vendor revisions from [4][5][6][8].

## KEY FACTS | Usage was low while legacy paths could persist

Stat: Mar 2021 | RFC 8996 deprecated TLS 1.0 and 1.1
Stat: 99.6% | TLS 1.2 of Safari TLS connections
Stat: 0.36% | Safari legacy 1.0/1.1, upper bound
Stat: 0.1% | TLS 1.1 in Mozilla telemetry
- The 0.36 percent and 0.1 percent figures describe each vendor's own connections, not all Internet services.
- RFC 7568 had already prohibited SSL 3.0 in June 2015; that is a separate earlier decision.
- RFC 9325, November 2022, prohibits 1.0 and 1.1 and still requires TLS 1.2 support.
- A tiny connection share can still include a critical internal device or a limited-upgrade population.
Caption: Evidence grade: Reported vendor telemetry; populations not comparable.
Notes: Apple figures from [4]; Mozilla figure from [5]; standards dates from [1][3][10].

## PART 1 | "Old TLS" is not one identical protocol

- NIST records that TLS 1.1 added explicit initialization vectors for CBC and revised padding-error treatment.
- TLS 1.2 expanded hash choices and introduced authenticated-encryption suites; TLS 1.3 redesigned the handshake and key derivation.
- TLS 1.1 was a real improvement over 1.0; deprecating it later does not make that gain imaginary.
- Protocol age is not itself an exploit, and a newer certificate does not modernize an old protocol feature.
Caption: Evidence grade: Confirmed NIST technical history.
Notes: Version changes from [2]; the "age is not an exploit" caution follows the study.

## PART 1 | SSL 3.0 retirement was a distinct earlier action

- RFC 7568 in June 2015 already prohibited SSL 3.0 and fallback to it, calling it insufficiently secure.
- Keep that 2015 SSL decision separate from the 2021 TLS 1.0 and 1.1 decision.
- "SSL" often persists as a product label, and a label is not evidence of the negotiated protocol.
- Grouping SSL 3.0, TLS 1.0 and 1.1 under one undated flaw obscures each version's own rationale.
Caption: Evidence grade: Confirmed normative standard.
Notes: RFC 7568 abstract and prohibition from [3]; continuity framing per the study.

## PART 2 | The 2018 browser announcements used measured adoption

- On October 15, 2018 Apple's WebKit notice planned Safari removal beginning March 2020.
- Apple reported TLS 1.2 on 99.6 percent of Safari connections, with combined legacy 1.0/1.1 below 0.36 percent.
- Mozilla announced the same target month and placed TLS 1.1 at 0.1 percent of connections.
- These were each vendor's telemetry, not a census of all Internet services; retain the denominator.
Caption: Evidence grade: Reported vendor telemetry; not a global census.
Notes: Apple figures and date from [4]; Mozilla figure and advance-notice framing from [5].

## PART 2 | Firefox's temporary reversal was documented

- A March 23 update re-enabled TLS 1.0 and 1.1 in Firefox 74 and 75 Beta to improve access to important information.
- A June 24 update said disablement would proceed in Firefox 78, scheduled for June 30.
- Firefox 78 release notes confirm disablement, with an error page for sites lacking TLS 1.2.
- The original March target cannot be reported as an uninterrupted completed rollout.
Caption: Evidence grade: Confirmed blog updates and release notes.
Notes: Reversal and resumed rollout from [6]; disablement confirmation from [7].

## PART 2 | Microsoft's amended notice separated browser families

- The March 31, 2020 notice postponed the planned change in light of global circumstances.
- Chromium-based Edge disabled the versions by default from version 84; the enablement policy was removed from version 91.
- An August 2022 amendment set September 20, 2022 for default-disablement in Internet Explorer and EdgeHTML.
- It distinguished disabling by default from removing support, and browser scope is not the whole operating system.
Caption: Evidence grade: Confirmed vendor notice with 2022 amendment.
Notes: Product-specific defaults, dates and scope from [8].

## PART 2 | Apple's platform notice differed in scope from Safari

- A September 21, 2021 developer notice marked TLS 1.0 and 1.1 deprecated on iOS 15, iPadOS 15, macOS 12, watchOS 8 and tvOS 15.
- Removal was set for future releases, and applications using the versions were told to transition.
- Applications with App Transport Security on all connections needed no change for that notice.
- This platform notice should be read alongside, not substituted for, the earlier Safari plan.
Caption: Evidence grade: Confirmed platform and API announcement.
Notes: Platform scope, versions and ATS note from [9]; the meaning of "deprecated" per the study.

## STANDARD | What the 2021 standard actually required

- RFC 8996 moved the old specifications to Historic status and prohibits negotiating TLS 1.0 and 1.1.
- A legacy record-layer version on an initial ClientHello is not, by itself, permission to negotiate an old protocol.
- The standard acknowledges interoperability failure with peers that cannot support newer versions, an explicit cost.
- A failed connection after raising the minimum can be the change working, yet it still needs investigation.
Caption: Evidence grade: Confirmed RFC text.
Notes: Historic status, negotiation rules and the interoperability cost from [1].

## STANDARD | Later guidance did not declare TLS 1.2 obsolete

- RFC 9325, November 2022, replaced RFC 7525; it prohibits 1.0 and 1.1 and requires TLS 1.2 support.
- It recommends TLS 1.3 support and preference when implemented, and warns against prematurely abandoning TLS 1.2.
- Retiring 1.0 and 1.1 does not mean every connection must use 1.3 or be deemed insecure.
- Support is not selection: an implementation may support several versions while preferring the newest.
Caption: Evidence grade: Confirmed normative guidance.
Notes: Version guidance and the interoperability warning from [10].

## DEFENDER VIEW | A case-specific migration review standard

- Record client and server versions, the TLS library or platform, where TLS terminates, and the negotiated version.
- Measure unsuccessful handshakes as well as successful modern traffic, since failures reveal clients that cannot connect.
- For business-critical services, identify the owner and supported upgrade path before removing compatibility.
- A temporary exception should carry explicit ownership and an end condition, not become a silent permanent state.
Caption: Evidence grade: Analytical recommendations drawn from the record.
Notes: Evidence standard and exception discipline from the study's section 10, grounded in [1][4][8].

## CROSS-CUTTING THEMES | Where the record is overstated or understated

Left: Easy to overstate
- "TLS 1.0 ended in 2021" as one universal switch-off.
- A shipped browser default read as completed deployment everywhere.
- Averaging vendor percentages into a single global adoption figure.
Right: Easy to understate
- Legacy clients, embedded devices and intranets could persist past the milestone.
- Disablement by default differs from removal of support.
- Deprecation does not retroactively protect past sessions.
Caption: Evidence grade: Mixed; each claim bounded to its source.
Notes: Overstatement and understatement contrasts across [1][4][5][8]; keep denominators and stages separate.

## CLOSE | Precision beats a single end-date claim

- March 2021 is the RFC milestone, not a universal deployment completion date.
- Deprecated by standard, removed from a given client, and unreachable anywhere are three distinct states.
- A configuration can re-enable old protocols, and deprecation does not retroactively protect past sessions.
- The lasting work is dependency removal; a changed default exposes a dependency, it does not upgrade the remote system.
Caption: Evidence grade: Case-specific conclusions, bounded.
Notes: Milestone-not-completion and dependency-removal points from sections 8, 10 and 11, resting on [1][9][10].
