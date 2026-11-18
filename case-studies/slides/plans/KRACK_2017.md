# Slide plan: KRACK 2017: Wi-Fi Key Reinstallation and the Problem of Security State

- Study: case-studies/KRACK_2017.md
- Cover title: KRACK 2017 / Key Reinstallation in WPA2 / The Problem of Security State
- Subtitle: A serious WPA2 weakness and a coordinated fix, not a documented mass breach; the lesson is a security system must remember what it has already done.
- Published: 15 November 2026
- Notes: House style; evidence-bounded; keeps potential exposure separate from confirmed compromise.

## EXECUTIVE SUMMARY | KRACK is a disclosure and engineering case, not a mass breach

- The public record shows a serious weakness and a coordinated response, no named campaign.
- No global victim count, stolen-data total or financial-loss estimate appears in the record.
- The defensive lesson is about state: a system must remember what it has already done.
- An operation safe at setup can turn dangerous when repeated after communication begins.
Caption: Evidence grade: a Confirmed weakness, no confirmed mass compromise.
Notes: Executive assessment and key takeaways, drawn across the record [1][2].

## KEY FACTS | The facts are bounded: ten CVEs, one coordinated fix cycle

Stat: 10 | CVE IDs grouped in CERT/CC VU#228519
Stat: 16 Oct | Public disclosure, 2017
Stat: 6 | Primary sources retained
- Vanhoef and Piessens disclosed key reinstallation in WPA2 handshakes in 2017.
- Vendor notice began about 14 July 2017; CERT/CC notified widely on 28 August.
- CERT/CC VU#228519 released 16 October 2017, revised 16 November 2017.
- CVE-2017-13082 identifies the fast-transition issue in the grouped set.
Caption: Evidence grade: Confirmed, the primary coordination and vendor records.
Notes: Counts and dates from the coordination and research records [1][2][3].

## PART 1 | Key reinstallation resets nonce and replay state, not AES

- Reinstalling an existing key can reset the nonce and replay state tied to it.
- The flaw is protocol handling, not a mathematical break of AES.
- Consequences vary: replay and decryption under AES-CCMP; forgery under TKIP or GCMP.
- Affected Android 6.0 implementations could install an all-zero key.
Caption: Evidence grade: Demonstrated under specified research conditions.
Notes: Vanhoef and Piessens research paper, abstract and selected passages [1].

## PART 1 | Agreement on a key is not the same as safe key state

- Separate three stages: agreeing key material, installing it, and the state protecting packets.
- Success at agreement does not make installation or ongoing state safe.
- A nonce needs uniqueness to stay safe; it is not a longer password.
- A replay counter tracks freshness; resetting state breaks assumptions even with the secret unknown.
Caption: Evidence grade: Inferred, original defensive analysis.
Notes: Original analysis building on the paper's findings [1].

## PART 2 | Disclosure dates mark different events, months apart

- Vendor notice around 14 July 2017; CERT/CC broadened it on 28 August 2017.
- Public disclosure landed 16 October 2017; CERT-EU advised on 17 October.
- The researcher did not claim to know whether the flaw was exploited in the wild.
- Changing the Wi-Fi password does not fix it; clients and access points need patches.
Caption: Evidence grade: Confirmed, the researcher and coordination records.
Notes: Researcher website, CERT/CC and CERT-EU records [2][3][4].

## PART 2 | Vendor fixes were real but narrower than their labels

- Android placed KRACK fixes at patch level 2017-11-06, not every November date.
- Android's no-active-exploitation note covered that bulletin's new issues only.
- Cisco's workaround addressed specific controllers, not every handshake variant.
- A month label is weaker evidence than a precise, verified patch level.
Caption: Evidence grade: Confirmed vendor records, bounded scope.
Notes: Android November 2017 bulletin and Cisco guidance 212390 [5][6].

## PART 2 | Exposure is a set of conditions, not the word Wi-Fi

- The attack needs wireless proximity to an affected access point and client.
- Proximity is not server-room access, nor reachable by an arbitrary internet host.
- Correct end-to-end encryption can protect content when the local network is untrusted.
- A rogue access point warrants investigation, not a conclusion that records were stolen.
Caption: Evidence grade: a Confirmed proximity condition, bounded by analysis.
Notes: The proximity condition from CERT/CC, with original scope analysis [3].

## DEFENDER VIEW | Rotating passwords does not remediate a state-handling flaw

- Emergency password changes are visible and countable but do not match this weakness.
- Rotation may be justified by separate evidence; reporting it as the fix misleads.
- State both action and purpose: a patch, an app control, a replacement, a credential change.
- Renaming or hiding a network needs a documented mechanism before counting as protection.
Caption: Evidence grade: Inferred, original analysis.
Notes: Original analysis, consistent with the researcher's mitigation boundaries [2].

## DEFENDER VIEW | Count endpoints and verify builds, not just infrastructure

- Build a ledger keyed to devices and roles: owner, model, OS, wireless part, support status.
- An honest unknown is more useful than an invented software version.
- Separate installation from availability: a release, a deploy job, and device evidence differ.
- Track a denominator and last-seen date so vanishing devices do not inflate completion.
Caption: Evidence grade: Inferred, an original recommendation.
Notes: An original inventory recommendation from the study.

## DEFENDER VIEW | Separate tracker states stop one green light hiding the gap

Avoid a single green status that cannot tell reading an advisory from confirming a fixed build.

| State | What it confirms |
|---|---|
| Assessed | Component matched to vendor scope |
| Remedy available | Update named, with prerequisites |
| Deployed | Job results and failures recorded |
| Verified | Fixed build and workflows confirmed |
| Exception | Compensating control or retirement |
Caption: Evidence grade: Inferred, an original recommendation.
Notes: An original remediation-stage recommendation from the study.

## DEFENDER VIEW | Retries must not reset the state they are meant to protect

- Retry logic enters as reliability; trouble starts when a repeat acts as a fresh instruction.
- Ask what stays invariant across retries and how a completed transition is recognized.
- Test duplicate events, delayed responses, restarts and mode changes, not just connection.
- Connect the protocol model to the real calls that install keys in drivers or hardware.
Caption: Evidence grade: Inferred, original engineering analysis.
Notes: Original engineering analysis building on the paper [1].

## MITRE MAPPINGS | This case maps to no ATT&CK technique or named actor

The study declines attribution and gives no exploitation sequence; these boundaries are deliberate.

| Mapping | Status |
|---|---|
| ATT&CK technique | Not mapped; the source set does not support it |
| Threat actor | Not attributed; no campaign evidence |
| Exploitation in the wild | Unknown; the researcher did not claim it |
Caption: Evidence grade: a Confirmed boundary, the study declines to map.
Notes: The study declines attribution and any exploitation claim [2].

## CROSS-CUTTING THEMES | Watch what the story overstates and understates

Left: Overstated risks
- Potential exposure reported as confirmed compromise.
- Password changes or network renames counted as fixes.
- A router firmware change read as every device being safe.
Right: Understated work
- Endpoint remediation alongside infrastructure.
- Verifying the actual build installed on each device.
- Unsupported gear on an explicit exception register.
Caption: Evidence grade: Inferred, an original synthesis.
Notes: Original synthesis across the study's analysis sections [1][2].

## CLOSE | Name the conditions and evidence behind every security claim

- A known protocol, strong cipher and working connectivity are incomplete assurances.
- Keep factual impact conditional; validate endpoints as well as infrastructure.
- Resist visible but causally unrelated changes standing in for the real fix.
- Make repeatable the ability to establish, determine, deploy and verify a remedy.
Caption: Evidence grade: Inferred, a final assessment.
Notes: Final assessment, resting on the six retained sources [1][2][3][4][5][6].
