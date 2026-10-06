# Roll Out Phishing-Resistant MFA and Conditional Access

> By the end of this guide you will have moved your organization from phishable MFA to phishing-resistant authentication (FIDO2 keys, passkeys, Windows Hello for Business, or certificate-based auth) enforced by Conditional Access for your admins and sensitive apps first, with legacy authentication blocked, break-glass accounts protected, and the help-desk reset path hardened against the Scattered Spider vector. Written for identity/IAM engineers, Microsoft Entra and M365 administrators, and the security lead who owns the "make MFA actually stop phishing" project. No prior passwordless-deployment experience assumed.

| Time | Difficulty | You need | You'll produce |
|---|---|---|---|
| A week for the admin pilot; one to two quarters to full enforcement | Intermediate-Advanced: identity changes lock people out when rushed | Entra ID P1/P2 (or Okta/Google equivalent), an authentication-policy admin role, a pilot group, a supply of FIDO2 keys or passkey-capable devices | A phased rollout plan, live Conditional Access policies requiring phishing-resistant MFA, a break-glass runbook, a help-desk verification protocol, and an adoption dashboard |

Ordinary MFA (SMS one-time codes, authenticator push, TOTP) is now routinely defeated: adversary-in-the-middle proxy kits (Evilginx-class) relay the whole session, push bombing wears users down, and SIM swaps steal the code. The fix is the class of methods NIST and CISA call *phishing-resistant*: authenticators cryptographically bound to the legitimate site's origin, so a proxy in the middle has nothing to replay. This guide operationalizes the library's identity references (the MFA-bypass-and-defenses material in the [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), the FIDO2/WebAuthn and Conditional-Access-as-Zero-Trust depth in the [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), and the AAL/phishing-resistance model in the [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md)) into a deployment you can execute. It is written against Microsoft Entra ID because that is the stack the references cover most deeply; Okta and Google Workspace equivalents are called out at each step. The learning path behind it is the [Identity & Access Management discipline](/disciplines/identity-access-management.md).

Why now: [CISA](https://www.cisa.gov/MFA) names FIDO/WebAuthn and PKI the only widely available phishing-resistant methods; the July 2025 [Scattered Spider advisory (AA23-320A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) puts phishing-resistant MFA plus help-desk hardening at the top of its mitigations; Microsoft's mandatory-MFA enforcement reached Azure resource management in [Phase 2 (from October 1, 2025)](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication); and Microsoft is making passkeys the [default authentication method in Entra ID from September 2026](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement). This is the highest-return identity control available in 2026.

## Before you start

- [ ] Read the identity references this guide sequences: the MFA bypass techniques and Entra vendor controls in the [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), the FIDO2/WebAuthn deep dive and Conditional Access structure in the [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), and the AAL3 / phishing-resistance definitions in the [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md). This guide assumes their vocabulary (AiTM, AAL3, verifier-impersonation resistance, authentication strength).
- [ ] The right admin role, not Global Administrator by reflex: Authentication Policy Administrator to edit the Authentication methods policy, Conditional Access Administrator for the CA policies, and Privileged Authentication Administrator if you will provision keys on behalf of users. Confirm against [Entra roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference).
- [ ] A licensing check. Conditional Access and authentication strengths need Entra ID P1; risk-based conditions and token protection need P2. FIDO2/passkeys, Windows Hello for Business, and certificate-based authentication (CBA) themselves are available without premium licensing; check current [Entra pricing](https://www.microsoft.com/security/business/microsoft-entra-pricing) and the [feature-licensing docs](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods).
- [ ] A pilot group you can afford to disrupt, and a second, separate ring of willing admins: admins go first in this rollout, not last.
- [ ] Hardware in hand: a supply of FIDO2 security keys (e.g., Yubico YubiKey 5 series, Feitian, Token2) for roles that need portable or shared-device auth, and confirmation that your workstations and phones can host platform passkeys / Windows Hello for Business.
- [ ] The Microsoft Graph PowerShell SDK installed if you script any of this (`Install-Module Microsoft.Graph`), and the [Microsoft plan for phishing-resistant passwordless deployment](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-deploy-phishing-resistant-passwordless-authentication) open as the vendor companion.

## Step 1: Inventory current authentication and find the phishable methods

You cannot enforce what you have not measured. Establish a baseline of who authenticates how, and where phishable methods and legacy protocols still live.

1. Pull the registration baseline. In the Entra admin center, open Protection -> Authentication methods -> Activity (the Authentication methods activity dashboard). It reports registration and usage, including the count of users capable of phishing-resistant passwordless authentication; that number is your headline metric for the whole project.
2. Get it as data for tracking over time. The report is exposed through Microsoft Graph at `/reports/authenticationMethods/userRegistrationDetails` ([API docs](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails)):

   ```powershell
   Connect-MgGraph -Scopes "AuditLog.Read.All","UserAuthenticationMethod.Read.All","Policy.Read.All"
   Invoke-MgGraphRequest -Method GET `
     -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$select=userPrincipalName,isMfaCapable,isPasswordlessCapable,methodsRegistered,isAdmin"
   ```

3. Find the legacy authentication. Legacy protocols (IMAP/POP/SMTP AUTH, older Exchange ActiveSync, Office 2010-era clients) bypass modern auth and every MFA control, so they are the escape hatch you must close before enforcement. In the Entra sign-in logs (or Log Analytics), pivot on the legacy client-app types:

   ```kusto
   SigninLogs
   | where TimeGenerated > ago(30d)
   | where ClientAppUsed in ("IMAP4","POP3","SMTP","Other clients","Exchange ActiveSync","Authenticated SMTP","MAPI Over HTTP")
   | summarize SignIns=count(), Users=dcount(UserPrincipalName) by ClientAppUsed, AppDisplayName
   | order by SignIns desc
   ```

4. List the phishable methods in use: SMS, voice call, and third-party TOTP are all AiTM-relayable. Note which users and, critically, which service accounts, scanners, and shared mailboxes depend on SMS/voice, because those break silently under enforcement.
5. Rank your populations by blast radius: privileged/admin roles first, then high-value users (finance, executives, IT, developers with production access), then the general population. This ranking drives every later step.

Checkpoint: You have a written baseline (the phishing-resistant-capable percentage, an inventory of legacy-auth clients with owners, a list of accounts still on SMS/voice, and a population ranking from admins outward).

Watch out: The service accounts and line-of-business integrations quietly using SMS or basic auth are exactly what turns "enforce phishing-resistant MFA" into an outage. Inventory them now; they get migration tickets, not surprises.

## Step 2: Choose your phishing-resistant methods

There are four phishing-resistant options; most organizations deploy two or three, matched to how people work. All four satisfy the built-in Entra Phishing-resistant MFA authentication strength and map to NIST SP 800-63B AAL3's requirement for a non-exportable private key with verifier-impersonation resistance.

| Method | Best for | Notes |
|---|---|---|
| FIDO2 security keys (hardware) | Shared workstations, kiosks, developers, admins, BYOD-heavy roles | Portable across devices; roaming authenticator; survives device loss/refresh; the CISA-recommended default |
| Passkeys (device-bound) in Microsoft Authenticator or platform (Windows Hello / Apple / Google) | Knowledge workers with a managed phone or PC | Private key created and stored on one device, never leaves it; Microsoft Authenticator device-bound passkeys are generally available |
| Windows Hello for Business | Windows fleet users at their assigned PC | Biometric/PIN bound to the device TPM; strong when the primary device is the PC |
| Certificate-based authentication (CBA) / PIV / CAC | Government, regulated, or existing-PKI shops | Smart-card certificates; the other method CISA names alongside FIDO |

Decision points:

- Do not deploy synced/consumer passkeys where you need assurance the credential can't leave a device; for AAL3-grade assurance, prefer hardware keys or device-bound passkeys over cloud-synced ones.
- Plan for the phone-less and the shared-device cases. Anyone without a personal managed device (frontline, manufacturing, healthcare floor) needs a hardware key, not a passkey-on-phone assumption.
- Restrict which keys you trust. Entra lets you enforce a FIDO2 key restriction by AAGUID (Authenticator Attestation GUID) and enforce attestation, so only vetted key models register. Attestation matters: without it, key restrictions only stop honest users; an attacker can spoof an allowed AAGUID ([Entra FIDO2 attestation](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor)).

Okta: the phishing-resistant possession factors are Okta FastPass (passwordless, delivered through the Okta Verify app) and Passkeys (FIDO2 WebAuthn) ([Okta phishing resistance](https://help.okta.com/oie/en-us/content/topics/architecture/pr/pr-overview.htm)). Google Workspace: hardware security keys and passkeys (both FIDO), enforced through 2-Step Verification and the [Advanced Protection Program](https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program).

Checkpoint: A written method-selection matrix (which population gets which method, which key models you'll allow by AAGUID, and whether you require attestation).

Watch out: "Passkeys for everyone" ignores the users who have no eligible device and the shared stations no passkey can cover. A method map that leaves a population unaddressed becomes a permanent SMS exception, the exact gap you're trying to close.

## Step 3: Enable the methods in the Authentication methods policy

Turn the chosen methods on for the pilot group before you require them anywhere. In Entra, all method management now lives in the Authentication methods policy; management of methods inside the legacy MFA and SSPR policy blades was [deprecated on September 30, 2025](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage), so if you haven't migrated, do that first.

1. Entra admin center -> Protection -> Authentication methods -> Policies. Enable Passkey (FIDO2) and target it at your pilot group. Under its options set Enforce attestation = Yes and configure Key Restrictions with the AAGUID allow-list from Step 2 ([enable passkeys/FIDO2](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-passkeys-fido2)).
2. Enable Windows Hello for Business (via Intune/GPO for the device fleet) and/or Certificate-based authentication if PKI is your path. CBA setup is its own project; see the [Entra CBA docs](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication).
3. Enable Temporary Access Pass (TAP). A TAP is a time-limited passcode an admin issues so a user can bootstrap their first passkey or key without an existing method; it is the on-ramp for passwordless registration and for break-glass setup in Step 6.
4. Do not disable SMS/voice yet. Enable the strong methods alongside the old ones; you remove the weak methods in Step 7 after adoption, not before.

Okta: configure Authenticator enrollment policies to make FastPass/passkeys available (and required) for the pilot group. Google: in the Admin console, allow security keys/passkeys and, for admins, stage the Advanced Protection Program.

Checkpoint: Pilot users can see and register a passkey/FIDO2 key (or WHfB/CBA), attestation and key restrictions are set, and TAP issuance works.

Watch out: Turning on Enforce attestation with an incomplete AAGUID allow-list will silently block registration of keys you actually own. Validate with one of each approved model before you widen the group.

## Step 4: Register keys and passkeys with the pilot

Enrollment is where rollouts stall; make the first credential effortless and supervised.

1. Self-service with a TAP (the default path). Issue each pilot user a TAP, have them go to [aka.ms/mysecurityinfo](https://aka.ms/mysecurityinfo) (My Sign-Ins -> Security info), choose Add sign-in method -> Passkey / Security key, and complete the biometric/PIN setup. Run the first wave as a supervised "registration station" session so problems surface immediately.
2. Admin-provisioned keys (for hardware at scale). Entra's FIDO2 provisioning APIs (public preview) let an admin register a security key on behalf of a user through Microsoft Graph, useful for pre-provisioning YubiKeys before handing them out. It requires the Authentication/Privileged Authentication Administrator role and the `UserAuthenticationMethod.ReadWrite.All` permission ([provisioning APIs announcement](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/public-preview-microsoft-entra-id-fido2-provisioning-apis/4062699)). Vendor sample flows exist (e.g., Yubico's on-behalf-of registration sample); verify the preview's current state and API shape against the live docs before building on it.
3. Register two authenticators per user where you can: a primary (say a passkey on the phone) and a backup (a hardware key in a drawer), so a lost device isn't an instant help-desk ticket and a recovery risk (see Step 7).
4. Track registration against the Step 1 dashboard; the phishing-resistant-capable count should climb with each wave.

Checkpoint: Every pilot user has at least one phishing-resistant credential registered (ideally two), and you have a repeatable registration-station script for the next waves.

Watch out: A TAP is a bearer credential; anyone who has it can register an authenticator. Keep TAP lifetimes short, one-time where possible, issue them through a verified channel, and treat TAP issuance as a privileged, logged action (it is a Scattered Spider-style target in its own right).

## Step 5: Build the Conditional Access policies

Now make the strong methods *required*, starting with admins, in report-only mode, before enforcement. In Entra, phishing resistance is expressed as an authentication strength applied through the Require authentication strength grant control. The built-in Phishing-resistant MFA strength accepts exactly three combinations: FIDO2 security key, Windows Hello for Business / platform credential, and certificate-based authentication (multifactor) ([authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)).

1. Get the built-in strength's ID rather than hardcoding a guess:

   ```http
   GET https://graph.microsoft.com/beta/identity/conditionalAccess/authenticationStrength/policies?$filter=policyType eq 'builtIn'
   ```

   Copy the `id` of the *Phishing-resistant MFA* strength from the response (it is a well-known built-in value, but read it from your tenant to be sure).

2. Policy 1: require phishing-resistant MFA for admins. Scope it to a group of your privileged roles (Global Administrator, Security Administrator, Exchange Administrator, Conditional Access Administrator, and the rest), applications All, grant = Require authentication strength -> Phishing-resistant MFA. Represented in Graph:

   ```json
   {
     "displayName": "CA-Admins-Require-Phishing-Resistant-MFA",
     "state": "enabledForReportingButNotEnforced",
     "conditions": {
       "users": { "includeRoles": ["<privileged role template IDs>"], "excludeGroups": ["<BreakGlassGroupId>"] },
       "applications": { "includeApplications": ["All"] }
     },
     "grantControls": {
       "operator": "OR",
       "authenticationStrength": { "id": "<phishing-resistant-strength-id-from-step-1>" }
     }
   }
   ```

   Note: you cannot combine Require authentication strength with the older Require multifactor authentication control in one policy; the strength supersedes it.

3. Policy 2: block legacy authentication. A separate policy scoped to client-app types `exchangeActiveSync` and `other`, grant = Block. This closes the Step 1 escape hatch; keep any inventoried service accounts excluded only until their migration tickets close.
4. Policy 3: require phishing-resistant MFA for sensitive apps / all users. Extend the strength requirement to your crown-jewel applications, then (in a later wave) to All users.
5. Policy 4: require device compliance for access to managed resources (grant = Require device to be marked as compliant, via Intune), layering device trust on top of identity, the Zero Trust posture in the [Zero Trust Reference](/ZERO_TRUST_REFERENCE.md).
6. Run report-only first. Leave the policies in `enabledForReportingButNotEnforced` and watch who would have been blocked in the sign-in logs / the CA What If tool for a week before flipping to `enabled`.

Okta: build an authentication policy (app sign-on policy) whose rule requires a phishing-resistant possession factor, and (this is the common miss) actually select the "Phishing resistant" constraint in the rule; without that checkbox, FastPass may fall back to a non-phishing-resistant method ([Okta phishing-resistant auth](https://help.okta.com/oie/en-us/content/topics/identity-engine/authenticators/phishing-resistant-auth.htm)). Google: enforce security-key/passkey 2SV for admin OUs and use Context-Aware Access (Enterprise Plus) to gate sensitive apps on identity, device, and location.

Checkpoint: Report-only policies exist for admin phishing-resistant MFA, legacy-auth block, sensitive-app strength, and device compliance; the report-only impact shows no surprise lockouts before you enforce.

Watch out: Enforcing an authentication strength without first confirming every targeted user has a *registered* method in that strength locks them out on the spot. Registration (Step 4) precedes enforcement, always. And break-glass exclusion (Step 6) must already be in place before you enable any blocking policy.

## Step 6: Protect the break-glass accounts

Emergency-access ("break-glass") accounts exist so a bad Conditional Access policy or an IdP outage can't lock you out of your own tenant. They are the one place you deliberately exclude from blocking CA policies, which makes hardening them non-negotiable.

1. Create two cloud-only accounts (`.onmicrosoft.com`, not federated, not tied to any one person), following [Microsoft's emergency-access guidance](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access).
2. Give them phishing-resistant credentials, not passwords-only. Current Microsoft guidance is to protect break-glass accounts with a passkey (FIDO2) or certificate-based authentication; both resist phishing and satisfy mandatory-MFA enforcement on their own. Use a TAP (Step 3) to perform the initial passkey registration, then store the hardware key(s) in separate physical safes.
3. Exclude them from the blocking CA policies (the `excludeGroups` in Step 5), but not from monitoring.
4. Alarm on every use. Alert the moment a break-glass account signs in (target detection-to-notification within about five minutes), because a legitimate use is rare and an illegitimate one is an emergency. Wire the alert into your SIEM.
5. Document and test. Write the runbook (who may invoke, dual-custody to retrieve the key, what to do after), and validate a sign-in on a schedule so the accounts don't rot.

Checkpoint: Two hardened, cloud-only, passkey/CBA-protected break-glass accounts exist, excluded from blocking policies, alarmed on use, with a tested runbook and physically secured credentials.

Watch out: A break-glass account left on a shared password in a vault, or excluded from the very alerts that would catch its misuse, is a backdoor with your name on it. Phishing-resistant credential, dual custody, and a five-minute alert: all three, or it isn't a break-glass account.

## Step 7: Harden the help desk and recovery paths

Phishing-resistant MFA moves the attacker to the softest remaining target: the help desk. Scattered Spider's signature move is a phone call impersonating an employee to get a credential or MFA reset. The [July 2025 CISA advisory](https://www.cisa.gov/sites/default/files/2025-08/aa23-320a-scattered-spider-508c.pdf) documents actors who research a target on business-to-business sites so they can pass knowledge-based identity checks, then talk the help desk into replacing the victim's authenticator. Close that door.

1. Retire the weak methods now that adoption is up. Remove SMS and voice as authentication methods for the migrated populations (Microsoft is itself [retiring Microsoft-provided SMS/voice](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement)). Every phishable method still enabled is a downgrade path an attacker will request by name.
2. Harden self-service password reset (SSPR) to require a strong method, and understand that with true passwordless you are reducing the password's role, not leaving its reset unguarded.
3. Replace knowledge-based verification at the help desk. Publicly discoverable facts (employee ID, manager, start date) are not identity proof. Move to something an attacker on the phone can't produce: a video call with a government ID check, a one-time code pushed to a *pre-registered* device or manager, an in-person/manager-approval step for factor resets, or a re-registration that itself requires an existing phishing-resistant factor or a supervised TAP.
4. Govern factor enrollment and reset as privileged actions. CISA's guidance pairs phishing-resistant MFA with controls on factor enrollment and recovery so the help desk cannot swap authenticators after a persuasive call. Log and alert on authenticator additions, TAP issuance, and MFA resets, especially outside business hours.
5. Train and drill the help desk on the vishing script: the pretexts and levers are catalogued in the [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md). A help desk that has practiced saying "I have to verify you through the callback process" is your real control here.

Checkpoint: Weak methods are removed for migrated users, SSPR is hardened, help-desk identity verification no longer relies on discoverable facts, and factor-enrollment/reset actions are logged and alerted.

Watch out: You can deploy perfect FIDO2 everywhere and still be owned through a five-minute phone call that resets a factor. The help-desk procedure is not a soft add-on to this project; post-Scattered Spider it is the control most likely to be attacked.

## Step 8: Enforce in waves, then monitor and measure

Flip from report-only to enforced, ring by ring, and turn the rollout into a standing metric.

1. Enforce in the order you ranked in Step 1: admins -> high-value users -> general population. Move a ring, hold for a week, watch the help-desk queue and the CA report, then move the next.
2. Drive the legacy-auth block to zero as the migration tickets close; each excluded service account is a tracked exception with an owner and a date, not a permanent carve-out.
3. Watch for the downgrade and the AiTM signals. Even with strong methods available, alert on unexpected use of weaker ones and on the AiTM/token-anomaly risk detections described in the [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md) (token-issuer anomaly, unfamiliar sign-in properties). Consider token protection and Continuous Access Evaluation (Entra P2) to bind and rapidly revoke sessions.
4. Report the numbers that matter monthly: percentage of users capable of phishing-resistant passwordless (from Step 1's dashboard), percentage of *sign-ins* using a phishing-resistant method, legacy-auth sign-ins trending to zero, and break-glass alerts (should be near-zero and always explained). Feed them into the same posture-metrics and drift process your M365 assessment uses ([Assess Your M365 Tenant with ScubaGear](/guides/ASSESS_M365_WITH_SCUBAGEAR.md)).
5. Escalate a bypass as an incident. A confirmed MFA-reset social-engineering attempt or an AiTM hit is identity compromise; hand off to the [phishing/identity playbooks](/IR_PLAYBOOKS.md).

Checkpoint: Phishing-resistant MFA is enforced for every ring, legacy auth is blocked with only tracked exceptions, the adoption and legacy-auth metrics are reported on a cadence, and a bypass attempt has a defined escalation.

Watch out: A rollout that reaches "enforced for admins" and stalls leaves the majority phishable, and attackers simply target the users you didn't finish. Enforcement is done when the general population is enforced and legacy auth is zero, not when the pilot succeeds.

## What good looks like

- Every privileged account signs in with a phishing-resistant method (FIDO2, passkey, Windows Hello for Business, or CBA), enforced by a Conditional Access authentication strength, and the admins went first, not last.
- Legacy authentication is blocked tenant-wide, and the phishing-resistant-capable percentage is a reported metric trending toward 100%.
- Break-glass accounts are cloud-only, passkey/CBA-protected, excluded from blocking policies, alarmed within minutes of use, and tested on a schedule.
- The help desk verifies identity with something an attacker on the phone cannot produce, and every factor enrollment/reset is a logged, alertable, privileged action.
- Registration is a supervised, repeatable process with a backup credential per user, so a lost phone is a minor ticket, not a lockout or a recovery risk.
- SMS and voice are gone as authentication methods for migrated users; the only downgrade paths left are ones you deliberately kept and monitor.

## Go deeper

In this library:

- [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md): the MFA-bypass techniques (AiTM, push bombing, SIM swap, recovery abuse) this guide defends against, plus Entra and Okta vendor-specific controls
- [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md): FIDO2/WebAuthn internals, passkeys, Conditional Access as Zero Trust enforcement, PAM, and break-glass design
- [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md): the AAL model, phishing-resistant MFA (AAL3), and the authentication-strength policy examples
- [Zero Trust Reference](/ZERO_TRUST_REFERENCE.md): the identity and device pillars behind the device-compliance and session-control policies
- [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md): the vishing and help-desk pretexts Step 7 hardens against
- [Identity & Access Management discipline](/disciplines/identity-access-management.md): the learning path that sequences these references
- [Assess Your M365 Tenant with ScubaGear](/guides/ASSESS_M365_WITH_SCUBAGEAR.md): the tenant-assessment guide whose CA and MFA findings this rollout remediates

External:

- [CISA: More than a Password / phishing-resistant MFA](https://www.cisa.gov/MFA) and the [Implementing Phishing-Resistant MFA fact sheet](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)
- [CISA/FBI Scattered Spider advisory AA23-320A (July 2025 update)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a): the help-desk social-engineering vector and mitigations
- [NIST SP 800-63B-4, Digital Identity Guidelines: Authentication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf): AAL3, phishing resistance, verifier-impersonation resistance
- [Microsoft: Plan a phishing-resistant passwordless authentication deployment](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-deploy-phishing-resistant-passwordless-authentication) and [Conditional Access authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [Microsoft: Manage emergency access (break-glass) accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Okta: Solutions for phishing resistance](https://help.okta.com/oie/en-us/content/topics/architecture/pr/pr-overview.htm), [Google Workspace: Advanced Protection Program](https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program)

*Guides are procedures, not gospel. Identity settings move fast and lock people out when wrong: verify every command, portal path, role name, and policy ID against the current official documentation, and test in report-only mode before you enforce.*

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
