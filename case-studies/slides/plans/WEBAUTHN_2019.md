# Slide plan: WebAuthn 2019: Standardizing Stronger Sign-In

- Study: case-studies/WEBAUTHN_2019.md
- Cover title: WebAuthn 2019 / Standardizing Stronger / Sign-In
- Subtitle: A W3C Recommendation gave the web origin-bound public-key sign-in that resists credential phishing; recovery and enrollment stay separate problems.
- Published: 18 November 2026
- Notes: Reference study of a standard, not an incident; no exploit code or live testing performed.

## EXECUTIVE SUMMARY | Advancement, not a breach to attribute

- WebAuthn belongs in the collection as an advancement, not an attack with victims.
- It changes how a service authenticates a user, reducing reliance on reusable secrets.
- A stronger authentication transaction is not the same as a completely secure account.
- It does not repair recovery, enrollment, authorization, endpoint security or sessions.
Caption: Evidence grade: Confirmed standards milestone; no incident attributed.
Notes: Executive-assessment framing from [S1] and [S2]; no exploit code reproduced.

## KEY FACTS | Dated documents, not adoption percentages

Stat: 2019 | WebAuthn Level 1 became a W3C standard
Stat: FIDO2 | WebAuthn is its browser and platform part
Stat: May 2022 | Platform expansion, a separate milestone
Stat: Level 1 | The fixed 2019 specification studied
- The announcement date is March 4, 2019; several browsers supported it, Safari as a preview.
- Publication of a standard and deployment by a service are different events.
- The study assigns no global account-takeover reduction to the 2019 publication.
- It adopts no vendor marketing statistics and invents no adoption percentage.
Caption: Evidence grade: Confirmed dated records; adoption claims withheld.
Notes: Milestone and support facts from [S1]; specification scope from [S2].

## PART 1 | A standard published is not a service deployed

- A standard establishes a shared technical reference; deployment needs integration and support.
- Without a common interface, each service and device pairing would need specialized work.
- Standardization makes reusable, interoperable implementations possible, not guaranteed.
- "WebAuthn supported" is the start of an inquiry, not an answer about real flows.
Caption: Evidence grade: Confirmed milestone; deployment not implied.
Notes: Milestone-versus-deployment distinction from [S1]; interpretation guidance from [S2].

## PART 1 | The Level 1 spec defines a scoped browser API

- The March 4 Recommendation defines creating and using public-key credentials per relying party.
- Relying-party checks cover challenge, origin, RP identifier, ownership, signature and verification.
- It separates a user-presence gesture from local user verification.
- It defines no backup or sharing protocol and encourages multiple credentials against loss.
Caption: Evidence grade: Confirmed; not a line-by-line conformance audit.
Notes: Specification scope and credential-loss note from [S2]; no production code shown.

## PART 1 | Phishing resistance is a specific, bounded property

- Later NIST guidance cites WebAuthn as phishing resistance through verifier-name binding.
- It is a claim about a defined authentication flow, not immunity from all deception.
- A signed-in user can still be sent a fraudulent invoice or persuaded to share information.
- A technology label alone does not set an assurance level; factors and configuration matter.
Caption: Evidence grade: Confirmed property; broader claims are analysis.
Notes: Verifier-binding and assurance points from [S3]; the flow framing is original analysis.

## PART 1 | Presence, verification and proofing stay distinct

- A presence gesture expresses participation; it does not prove local verification.
- A local verification is not a fresh investigation of someone's civil identity.
- Separate three questions: which account, what this transaction proves, what access it grants.
- Correct cryptography can still bind a credential to the wrong account during enrollment.
Caption: Evidence grade: Confirmed distinction; deployment advice is analysis.
Notes: Presence/verification wording from [S2]; the three-question model is original analysis.

## PART 2 | Registration deserves the same scrutiny as login

- Registration happens less often but decides what evidence the account later accepts.
- Decide how a user is authorized to add a credential and how they learn it changed.
- A successful creation response is not the same as completed account enrollment.
- Adding a credential should preserve existing access until the replacement is verified.
Caption: Evidence grade: Original deployment analysis built on the spec.
Notes: Registration model developed from [S2]; strong cryptography does not remove state design.

## PART 2 | Passkeys are later terminology, not 2019

- FIDO describes passkeys as FIDO credentials using WebAuthn and CTAP, not a new standard.
- It distinguishes synced passkeys from device-bound passkeys, with local PIN or biometrics.
- Biometric processing stays local; the biometric itself is not sent to the website.
- These are current explanations, not proof every 2019 implementation matched them.
Caption: Evidence grade: Confirmed current terminology; not backdated to 2019.
Notes: Passkey definitions and local-biometric point from [S4]; synchronization not assumed universal.

## PART 2 | The milestones stay distinct

Each source establishes its own moment and nothing more.

| Milestone | What the source establishes | What it does not establish |
|---|---|---|
| March 4, 2019 | WebAuthn Level 1 Recommendation | Universal website adoption |
| May 5, 2022 | Announced platform expansion | Immediate availability of every flow |
| FIDO terminology | Synced and device-bound distinctions | One portability guarantee |
| NIST guidance | Assurance and lifecycle requirements | Compliance from a passkey label |
Caption: Evidence grade: Confirmed dated records; non-claims kept explicit.
Notes: Milestone table condensed from [S1], [S5], [S4] and [S3].

## PART 2 | Portability has four separate meanings

- Interoperability: can a supported authenticator and client join the service's flow.
- Cross-device use: can a person authenticate on one device using another's credential.
- Synchronization: does credential availability extend across devices through a provider.
- Provider migration: can a person move credential arrangements to another ecosystem.
Caption: Evidence grade: Original classification to prevent ambiguous requirements.
Notes: Four-way portability split is original analysis from [S4]; test reports should record environment and date.

## DEFENDER VIEW | Recovery is another path to account control

- NIST lifecycle guidance separates recovery from authentication and requires event notification.
- If a weak support process can replace a strong credential, security depends on that process too.
- Making recovery impossible can deny legitimate users access to essential services.
- A backup authenticator still needs a process and must not share the primary's loss event.
Caption: Evidence grade: Confirmed lifecycle guidance; conclusion is analysis.
Notes: Recovery and notification points from [S3]; the threat-model conclusion is original analysis.

## DEFENDER VIEW | Phishing resistance does not replace sessions

- Authentication fixes access at a point in time; applications keep a continuing session.
- A compromised endpoint or mishandled session creates problems outside credential phishing.
- Sensitive actions may need fresh authentication, not blanket authority from one login.
- Incident response should separate credential, session and recovery-method investigations.
Caption: Evidence grade: Original review framework consistent with the sources.
Notes: Session and incident framing developed from the study; a control is evaluated against its threat.

## DEPLOYMENT | Gates and measurable outcomes

These gates are original recommendations, not a certification checklist.

| Gate | Evidence to request | Misleading shortcut |
|---|---|---|
| Enrollment | Correct account binding and authorized additions | A creation prompt appeared |
| Sign-in | Intended verification policy and negative tests | One successful demonstration |
| Recovery | Documented ownership checks and notification | Support can reset anything quickly |
| Removal | Lost credentials no longer accepted | Device deleted from a local screen |
Caption: Evidence grade: Original gates; not NIST compliance.
Notes: Gates condensed from the study's deployment table; count completed enrollments apart from invitations.

## CLOSE | Make trust boundaries explicit

- A common foundation for stronger web authentication is the real 2019 achievement.
- State what the transaction proves, and how credentials are enrolled and replaced.
- State what happens when a device is lost, a provider changes or a session looks suspicious.
- Separate the standard from later passkey conveniences, and a strong flow from a secure account.
Caption: Evidence grade: Case-specific conclusions, bounded to the record.
Notes: Final-assessment synthesis across [S1] through [S5]; neither celebration nor blanket skepticism.
