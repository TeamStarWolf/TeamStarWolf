# Slide plan: PetitPotam and coerced authentication

- Study: case-studies/PETITPOTAM_CVE_2021_36942.md
- Cover title: Coercion / Relay / Hardening
- Subtitle: How PetitPotam coerced Windows hosts to authenticate, and why one patch did not close the NTLM relay path to AD CS.
- Published: 18 November 2026
- Notes: The cover frames PetitPotam as a multi-stage chain rather than a single domain-takeover bug.

## CONTEXT | What PetitPotam actually is
- PetitPotam is a 2021 technique that coerces a Windows host to authenticate to an attacker-chosen machine.
- It abuses MS-EFSRPC methods; the researcher noted that disabling the EFS service did not appear to stop it.
- The name became shorthand for a larger relay-to-certificate chain, not a single flaw.
- It is tracked as CVE-2021-36942, with Microsoft guidance issued under ADV210003.
Caption: Evidence grade: Confirmed (CVE record and researcher README)
Notes: Names the technique and separates it from the end-to-end chain it can feed.

## PRIMITIVE | Coercion is a trigger, not an auth bypass
Left: What coercion does
- Makes a target host start an authentication attempt toward a chosen destination.
- Answers only why an authentication begins, not who is trusted.
- Operates on the source computer that can be induced to authenticate.
Right: What it is not
- It does not bypass authentication or crack a password.
- It does not by itself grant access to any service.
- Blocking one coercion route leaves relay weaknesses on accepting services untouched.
Caption: Evidence grade: Inferred (architectural reading of CERT/CC note)
Notes: Keeps the coercion primitive distinct from an authentication bypass.

## CHAIN | Three stages, not one bug
Domain takeover requires all three stages to line up, not any single component.

| Stage | Acts on | Defensive control |
| --- | --- | --- |
| Coerce | Source Windows host | Block the coercion route, patch the call |
| Relay | Attacker intermediary | Channel binding, reject out-of-context auth |
| Enroll | AD CS web enrollment | EPA plus HTTPS on enrollment services |
Caption: Evidence grade: Inferred (two-stage model from reviewed records)
Notes: Shows why calling it a "domain takeover bug" overstates any one piece of the chain.

## PROTOCOL | MS-EFSRPC as the coercion surface
- The technique induces authentication through EFSRPC methods exposed on Windows hosts.
- The retained README identifies more than one interface route to the behavior.
- The pre-patch anonymous path ran through the EfsRpcOpenFileRaw call over LSARPC.
- CERT/CC cautions that other methods can also coerce authentication.
Caption: Evidence grade: Confirmed (researcher README and CERT/CC note)
Notes: Names the protocol surface without providing an operational recipe.

## TARGET | Why AD CS enrollment raised the stakes
- AD CS web enrollment can turn an accepted authentication context into an X.509 certificate.
- KB5005413 names Certificate Authority Web Enrollment and Certificate Enrollment Web Service as the exposed services.
- A certificate can act as a credential, not merely a record that a request occurred.
- CERT-FR describes relaying a domain controller account to AD CS as a path to wider directory compromise.
Caption: Evidence grade: Reported (Microsoft KB5005413 and CERT-FR)
Notes: Explains why enrollment endpoints sit inside the identity security boundary.

## PATCH | What CVE-2021-36942 did and did not do
- The August correction blocked the unauthenticated EfsRpcOpenFileRaw call reachable through LSARPC.
- CERT/CC describes continued authenticated access through EFSRPC and other LSARPC functions.
- "Requires authentication" is not "requires a typed password"; domain single sign-on can satisfy it.
- CERT/CC therefore characterized the fix as partial, not a complete close of the relay class.
Caption: Evidence grade: Confirmed (CERT/CC VU#405600)
Notes: Makes the word "partial" concrete without overstating what stayed reachable.

## TIMELINE | July guidance arrived before the August patch
The response spanned advisory, configuration, and patch obligations that overlapped in time.

| Date (2021) | Source | What it added |
| --- | --- | --- |
| 23 July | Microsoft ADV210003 | Advisory on AD CS NTLM relay risk |
| 26 to 29 July | Singapore CSA | EPA and disable-HTTP guidance; NTLM warning |
| 2 August | CERT/CC VU#405600 | Partial-scope analysis (revised 5 October) |
| 11 August | JPCERT/CC | Patch and AD CS mitigation as concurrent duties |
Caption: Evidence grade: Confirmed (dated government and CERT advisories)
Notes: Shows that service hardening and patching were concurrent, not alternatives.

## RELAY | The password was never the object
- Extended Protection, explained by Microsoft in 2009, counters relay without the password being learned.
- A relay abuses where a valid authentication exchange is accepted, not a weak password.
- PetitPotam reused an older NTLM relay class rather than inventing it in 2021.
- The defensive question is whether a service verifies that authentication belongs to its own context.
Caption: Evidence grade: Reported (Microsoft MSRC 2009 explanation)
Notes: Reframes the risk away from a password-cracking narrative.

## REMEDY | EPA and HTTPS as a combined control
Left: Extended Protection for Authentication
- Binds authentication to the intended service and channel.
- "Required" rejects unsupported authentication; "accepting" still admits older clients.
- Both client and server must support it for the connection to benefit.
Right: HTTPS on enrollment
- TLS confidentiality alone does not prove authentication cannot be relayed.
- KB5005413 pairs required EPA with HTTPS on the enrollment services.
- CES also needs its configuration file updated to match the IIS setting.
Caption: Evidence grade: Reported (Microsoft KB5005413 and 2009 EPA note)
Notes: Treats binding and transport security as related but distinct requirements.

## NTLM | Audit before you disable
- Singapore's alert warned that disabling NTLM could break applications that still depend on it.
- CERT-FR recommends auditing privileged systems' outgoing NTLM before enforcement.
- Auditing reveals dependencies; it does not by itself stop the relay class.
- A migration plan must identify which critical systems still initiate NTLM and why.
Caption: Evidence grade: Reported (Singapore CSA and CERT-FR)
Notes: Separates discovery of NTLM dependencies from the enforcement that changes behavior.

## TERMS | Golden-ticket language needs care
- CERT/CC used golden-ticket language for the potential certificate-to-ticket consequence.
- MITRE defines a golden ticket narrowly as a ticket forged with the KRBTGT secret.
- A certificate-based ticket request and a KRBTGT forgery are not identical operations.
- The study does not infer that the KRBTGT secret was obtained in any named case.
Caption: Evidence grade: Confirmed (MITRE T1558.001 and CERT/CC note)
Notes: Prevents a familiar label from smuggling in an unproven compromise claim.

## METRICS | Evidence at a glance
Stat: 2021 | year PetitPotam drew public attention
Stat: 10 | primary sources cited in the study
Stat: 3 | chain stages: coerce, relay, enroll
Stat: 2 | AD CS enrollment services in KB5005413
- Each number traces to a named primary record rather than an aggregate estimate.
Caption: Evidence grade: Confirmed (counts drawn from cited sources)
Notes: Anchors the case in traceable figures without implying a victim count.

## VERIFY | Questions tied to the actual chain
- Which privileged hosts can still initiate NTLM authentication?
- Which AD CS enrollment services are enabled, and is authentication bound to the channel?
- Are effective application settings consistent with the administrative interface?
- Was the specific Windows correction applied, and does an inventory alone prove enrollment is safe?
Caption: Evidence grade: Inferred (verification logic from the reviewed chain)
Notes: Replaces a generic checklist with questions aimed at distinct failure modes.

## LIMITS | What the records do and do not establish
- The records establish a coercion technique, a high-impact AD CS relay scenario, and a bounded August patch.
- A demonstrated component behavior is not an inventory of affected organizations.
- The sources do not establish a global victim count, loss figure, or named campaign attribution.
- Preventing future relay does not confirm that previously issued credentials were reviewed.
Caption: Evidence grade: Confirmed (scope statements in the study)
Notes: Closes on the boundary between a demonstrated technique and a confirmed organizational compromise.
