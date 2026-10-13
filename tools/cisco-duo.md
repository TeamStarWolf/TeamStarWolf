# Cisco Duo

*Cisco (Cisco Security / Security Cloud; Duo originally acquired by Cisco in 2018) · Multi-factor authentication (MFA) / adaptive access / device trust / access management; a component of Cisco's identity and Zero Trust (Secure Access / ITDR) portfolio*

Cisco Duo is a cloud-delivered MFA and secure-access platform that verifies user identity and device trust before granting access to any application, on-prem or cloud. It solves the problem of credential-based attack by adding strong, phishing-resistant, user-friendly authentication plus device-health and trust checks at the access point. Duo is positioned as an easy-to-deploy, application-agnostic access layer that overlays existing identity providers, and it now anchors Cisco's broader identity threat detection and response (ITDR) and Secure Access (SSE) story via Cisco Identity Intelligence. For vulnerability mitigation it is a fast-to-deploy compensating control that blocks the credential/access path to vulnerable systems.

## Capabilities & architecture

**Core capabilities**
- Multi-factor authentication: Duo Push (with number/verified push and fraud controls), passwordless and FIDO2/passkeys, WebAuthn, biometrics, TOTP, phone call/SMS, hardware tokens
- Phishing-resistant authentication (FIDO2 security keys, platform authenticators, Verified Duo Push)
- Single sign-on (Duo SSO) and Duo Central/Directory as a cloud IdP; federation to existing IdPs (Entra ID, Okta, AD)
- Device Trust and Trusted Endpoints: distinguishes managed vs. unmanaged devices and allows access only from trusted/registered endpoints; integrates with MDM/UEM (Intune, Jamf) and Duo Desktop/Device Health app
- Device health / posture checks: OS version, disk encryption, firewall, screen lock, password status, browser/plugin versions at each access attempt
- Adaptive / risk-based authentication: Risk-Based Authentication that steps up based on signals (location, Wi-Fi fingerprint, novel device, attack patterns) and Trust Monitor anomaly detection
- Policy engine: per-application and per-group policy for user location, device, network, authentication method, and session
- Duo Network Gateway (DNG) and Duo Passport: VPN-less remote/ZTNA access to on-prem web apps, SSH, RDP; Passport provides seamless re-authentication across apps on a trusted device
- Cisco Identity Intelligence (ITDR/ISPM): ingests identity data from IdPs to surface identity posture risks, dormant/privileged accounts, MFA gaps, and detect identity attacks (MFA flooding, session hijack, inactive-account probing)
- Privileged session controls (higher tiers) and admin API / reporting / detailed logs
- Broad application integrations: VPNs, RDP/RADIUS, cloud and SaaS apps, on-prem web apps, Unix/Linux PAM, Windows logon

**Architecture & deployment.** Primarily SaaS: the Duo cloud service handles policy evaluation and the second factor. Applications integrate via a lightweight Duo Authentication Proxy (on-prem connector for RADIUS/LDAP, AD sync), native app integrations/SDKs, or standards-based SSO (SAML/OIDC). A user authenticates to the app/IdP (primary factor) and Duo performs the second factor and device/policy check out-of-band via the cloud. Device trust uses the Duo Desktop agent and/or MDM integration; Trusted Endpoints can also key off management certificates. Duo Network Gateway is a customer-deployed reverse proxy for VPN-less access. Cisco Identity Intelligence is delivered as a shared cloud service via Cisco Security Cloud Control, consuming identity-provider data and feeding context to Duo, Cisco Secure Access (SSE), and Cisco XDR. Agentless options exist for many web/SSO flows.

**Editions & licensing.** Per-user, per-month subscription (list, verify): Free (up to 10 users, pilots), Essentials (~$3), Advantage (~$6), Premier (~$9). Sold in user increments; enterprise negotiated rates typically below list. Essentials provides core phishing-resistant MFA, SSO, Duo Directory, and unlimited app integrations (Trusted Endpoints placement varies by current packaging — verify on duo.com). Advantage adds Risk-Based Authentication, Trusted Endpoints/device trust depth, Cisco Identity Intelligence (ITDR/ISPM), Duo Passport, and Duo Network Gateway capabilities. Premier adds VPN-less remote access via Duo Network Gateway and privileged session controls, and the fullest Passport experience. Duo is also bundled into Cisco suites (e.g., Secure User Protection Suite; entitlement differs by purchase date — Premier before 4 Dec 2024, Advantage after).

**Key integrations.** Identity providers: Microsoft Entra ID, Okta, Ping, on-prem Active Directory (as external MFA or federated); MDM/UEM for device trust: Microsoft Intune, Jamf, VMware Workspace ONE, and generic MDM; VPN / network: Cisco AnyConnect/Secure Client, Palo Alto, Fortinet, F5, Citrix, and RADIUS/LDAP apps via Authentication Proxy; Cisco ecosystem: Cisco Secure Access (SSE), Cisco XDR, Cisco Identity Intelligence, Cisco Security Cloud Control; SIEM/log: log export / Admin API to Splunk and other SIEMs; SaaS and on-prem web apps via SAML/OIDC and Duo SSO; Unix/Linux PAM and Windows logon.

**Differentiators**
- Fastest, simplest MFA deployment in the market with strong UX (Duo Push) driving high adoption — a practical advantage for emergency rollout
- Application- and IdP-agnostic overlay: protects legacy and modern apps without ripping out the existing identity stack
- Device trust / Trusted Endpoints without necessarily owning the full MDM — strong posture gating at access time
- Now part of a broader Cisco ITDR stack (Duo + Identity Intelligence + Secure Access + XDR) giving identity-centric SSE and continuous risk
- Duo Passport delivers VPN-less, re-auth-light experience across apps on a trusted device

**Limitations & considerations**
- Not a full IdP/directory replacement for large enterprises — typically overlays Entra/Okta/AD rather than replacing them; Duo Directory/SSO is lighter-weight
- Not an IGA or PAM solution: no entitlement governance, no credential vaulting or privileged-session recording at CyberArk depth (privileged session controls are limited and tier-gated)
- Feature/tier packaging shifts (Trusted Endpoints, Passport, Identity Intelligence placement has moved between Essentials/Advantage/Premier) — must verify current editions
- Device health depends on the Duo Desktop agent or MDM integration; unmanaged/BYOD coverage can be partial
- Authentication Proxy and Duo Network Gateway are customer-run components that need sizing, HA, and patching themselves
- Risk-Based Authentication and Identity Intelligence require higher tiers; lower tiers are MFA-centric only

## Vulnerability-mitigation role

Rapid-deploy identity compensating control at the access boundary. When a CVE exposes an internet-facing app, VPN, or workload management interface, Duo can enforce MFA / phishing-resistant MFA and device-trust on that access path in hours, so stolen or sprayed credentials and session-based exploits cannot reach the vulnerable service. Trusted Endpoints restricts access to known managed devices (blocking exploitation from attacker-controlled endpoints). Device health policy can block devices that are themselves unpatched for the CVE (e.g., require a minimum OS/browser/agent version), effectively quarantining vulnerable clients until they update — a direct endpoint-side mitigation. Risk-Based Authentication and Identity Intelligence detect and step up on the anomalous access patterns that accompany active exploitation. It mitigates the access and credential vectors around a vulnerability rather than fixing the flaw itself.

**VM lifecycle:** Prioritize · Mitigate · Monitor/Detect · Validate

**Framework mapping:** NIST CSF 2.0: PR (Protect) — PR.AA Identity Management, Authentication, and Access Control (primary); DE (Detect) — DE.CM via Trust Monitor / Identity Intelligence; CIS Controls v8: 6 (Access Control Management — 6.3/6.4 MFA), 5 (Account Management), 4 (Secure Configuration — device posture gating), 1/2 (device/software inventory via endpoint posture), 13 (Network Monitoring — adjacent via Identity Intelligence); MITRE ATT&CK mitigations: M1032 Multi-factor Authentication (primary), M1036 Account Use Policies, M1017/ M1026 (privileged access, higher tiers), M1035 Limit Access to Resource Over Network (DNG/ZTNA)

**In a critical-CVE scenario.** Hour 0-24: for an exposed internet-facing app or VPN, attach a Duo application policy requiring phishing-resistant MFA and (where possible) Trusted Endpoint for that app/group; disable weak factors (SMS) for the affected path. If the CVE is client-side, set a device-health policy requiring the patched minimum OS/browser/agent version so unpatched endpoints are blocked from the sensitive app. Enable/raise Risk-Based Authentication to step up on anomalies. Hour 24-72: review Duo authentication logs and Trust Monitor / Cisco Identity Intelligence for suspicious access, MFA-flood, impossible-travel, and new-device events tied to the CVE; tighten policy to managed devices and known networks; coordinate with the IdP (Entra/Okta) for credential resets. For a cloud workload's admin/management access, front it with Duo SSO + device trust. Validate via Duo reporting that enforcement is applied; keep policy until the app/endpoints are patched.

## Validation & telemetry

**Log sources**
- Duo Admin Panel > Reports (Authentication Log, Administrator Actions, Telephony).
- Admin API pull endpoints: /admin/v2/logs/authentication, /admin/v2/logs/activity, /admin/v1/logs/administrator, /admin/v1|v2/logs/telephony. Requires a Duo Admin API application (created only by an Owner) with log read permission.
- SIEM connectors that poll the Admin API: Splunk Duo add-on (sourcetypes cisco:duo / duo:authentication), Microsoft Sentinel Cisco Duo connector (custom *_CL table), Elastic cisco_duo integration, Panther/Sekoia parsers.
- On-prem component health: the Duo Authentication Proxy service and its authproxy.cfg (for RADIUS/LDAP-proxied apps).

**Telemetry format / transport.** JSON over HTTPS REST (Admin API, HMAC-SHA1 signed requests). Timestamps are Unix seconds plus an ISO-8601 isotimestamp. SIEM add-ons (Splunk, Sentinel, Elastic, Panther) re-emit as JSON and map to Splunk CIM Authentication.

**Control-presence check (present & configured?).** Duo is a cloud 2FA service, so 'control present' is verified through the Admin API/console, not device keys. (1) MFA is actually required for an app: the integration exists — GET /admin/v1/integrations — and its assigned policy requires two-factor (console: policy shows 'Require two-factor authentication'; check via policy API/summary). (2) Users can satisfy MFA: GET /admin/v1/users → status == 'active' with enrolled phones/tokens (so 2FA cannot be silently skipped as bypass). (3) For proxied apps, confirm the Duo Authentication Proxy Windows/Linux service is running and authproxy.cfg points at the right app. There is no registry/sensor on the endpoint — enforcement lives at the Duo integration + policy.

**Validation signals (actually working?)**
- /admin/v2/logs/authentication records with result == 'success' AND a real factor (duo_push, passcode, sms_passcode, phone_call, yubikey_passcode, u2f_token) — proves a second factor was genuinely completed for that login.
- result == 'denied' with a policy-driven reason (e.g. denied_by_policy, locked_out, anomalous_push, location_restricted, factor_restricted, out_of_date / no_duo_certificate for Trusted Endpoints, deny_unenrolled_user) — proves active blocking, not just configuration.
- result == 'fraud' (user hit 'report fraud' on a push) — proves push-phishing/MFA-fatigue resistance is operating.
- Distinguish configured-vs-effective: result == 'success' with factor == 'remembered_device' or 'trusted_network' means the policy let the user SKIP a live factor — it counts as success but is NOT proof a fresh second factor ran.

**Key events / fields / tables / APIs**
- Endpoint: GET /admin/v2/logs/authentication (v2 paging uses next_offset = [timestamp_ms, txid]; v1 is deprecating).
- Top-level fields: result (success|denied|fraud), reason (failure/outcome reason), factor, event_type (authentication|enrollment), txid, timestamp, isotimestamp, email, trusted_endpoint_status, ood_software.
- Nested objects: user{key,name,groups}; access_device{ip, hostname, location, browser, browser_version, os, flash_version, java_version, is_encryption_enabled, is_firewall_enabled, is_password_set, trusted_endpoint_status}; auth_device{ip, location, name}; application{key, name}.
- factor enumerated values (per Panther schema — may not be exhaustive/current): duo_push, phone_call, passcode, sms_passcode, sms_refresh, duo_mobile_passcode, yubikey_passcode, hardware_token, digipass_go_7_token, bypass_code, u2f_token, remembered_device, trusted_network.
- Config/admin evidence: /admin/v1/logs/administrator (fields action, username, object, description) and /admin/v2/logs/activity capture policy edits, bypass-code creation, and API-app creation — these are NOT in the authentication log.

**Example queries**

*Collect + validate: pull the auth log window, then filter to active policy denials.* (Duo Admin API (REST))

```
GET /admin/v2/logs/authentication?mintime=<epoch_ms>&maxtime=<epoch_ms>&limit=1000   (HMAC-SHA1 signed; iterate using the returned next_offset=[timestamp_ms,txid]). Then keep records where result=="denied" and reason indicates a policy (e.g. denied_by_policy, location_restricted, out_of_date).
```

*Validation: confirm a live second factor is actually completing per application (not remembered-device skips).* (Splunk SPL)

```
sourcetype="cisco:duo" event_type=authentication result=success factor=duo_push
| stats count by user.name application.name
| sort - count
```

*Validation: surface active blocks and fraud reports with their reasons.* (Splunk SPL)

```
sourcetype="cisco:duo" event_type=authentication (result=denied OR result=fraud)
| stats count by result reason factor application.name
```

**How it mitigates (mechanism).** Duo is an inline second-factor gate (direct integration or RADIUS/LDAP proxy): it intercepts the primary-auth result and returns 'allow' to the relying application only after a verified second factor succeeds, so a stolen password alone yields result=denied / no_response. The per-attempt result + factor + reason in the authentication log is the proof the gate ran and how it resolved.

**Logging gotchas**
- Admin API data window is 180 days and records are available only up to ~2 minutes before now; the v2 authentication log uses a special two-value next_offset (timestamp + txid) unlike other endpoints, so naive paging drops or duplicates records.
- result=='success' with factor 'remembered_device' / 'trusted_network' means 2FA was policy-skipped — it inflates 'MFA worked' counts without a live factor; alert on their proportion.
- Duo explicitly warns undocumented fields may change or be removed and new ones appear at any time — build tolerant parsers; imported soft-token auth events omit the token ID, so you cannot join auth logs to token records by ID.
- Only attempts that actually reach Duo are logged; if SSO/RADIUS fails before calling Duo, or an app isn't behind Duo, nothing appears — absence of a deny is not proof of protection.
- Bypass-code creation and policy weakening show up only in the administrator/activity logs, not the auth log; collect those separately or you'll miss the control being disabled.

## Documentation & repositories

_Official documentation & manuals_
- [Duo documentation hub](https://duo.com/docs)
- [Duo Administration – Admin Panel Overview](https://duo.com/docs/administration)
- [Duo administrator roles](https://duo.com/docs/administration-admins)
- [Cisco Security Cloud Control provisioning for Duo](https://duo.com/docs/cisco-security-cloud-control)
- [Getting Started with Duo](https://duo.com/docs/getting-started)
- [Duo Lift-Off Guide (deployment best practices, PDF)](https://duo.com/assets/pdf/duo-liftoff-guide.pdf)

_API & developer docs_
- [Duo Admin API (users, phones, tokens, logs)](https://duo.com/docs/adminapi)
- [Duo Auth API (low-level 2FA REST API)](https://duo.com/docs/authapi)
- [Duo Accounts API (parent/child account management)](https://duo.com/docs/accountsapi)

_GitHub (official)_
- [Duo Security GitHub organization](https://github.com/duosecurity)
- [duo_client_python (Auth/Admin/Accounts API client)](https://github.com/duosecurity/duo_client_python)
- [duo_client_java](https://github.com/duosecurity/duo_client_java)
- [duo_api_csharp](https://github.com/duosecurity/duo_api_csharp)
- [duo_api_golang](https://github.com/duosecurity/duo_api_golang)
- [duo_api_nodejs](https://github.com/duosecurity/duo_api_nodejs)
- [duo_log_sync (official SIEM log ingestion tool)](https://github.com/duosecurity/duo_log_sync)

_Community / integration / detection repos_
- [SigmaHQ detection rules (Duo/MFA authentication logs)](https://github.com/SigmaHQ/sigma)
- [Elastic detection-rules (identity/MFA, incl. Duo-relevant)](https://github.com/elastic/detection-rules)
- [Duo apps & add-ons on Splunkbase (SIEM integration)](https://splunkbase.splunk.com/apps?keyword=duo)

_Learning & reference_
- [Duo Guide to Two-Factor Authentication (end-user/enrollment)](https://guide.duo.com/)
- [Duo Security blog](https://duo.com/blog)
- [Duo product/solutions knowledge base](https://duo.com/docs)

> Note: LIVE-VERIFIED via WebSearch 2026-10-08. Duo is owned by Cisco. Admin onboarding is migrating to Cisco Security Cloud Control (SCC): admins created via SCC after 2026-05-11 must sign in through SCC rather than admin.duosecurity.com directly. Admin API and Auth API are SEPARATE Duo application types with separate key pairs; Admin API requires Essentials/Advantage/Premier plan while Auth API is also available on Free/trial. Auth API clients using certificate pinning required updates before 2026-04-15 (see Duo KB 9451). thebananastand.duo.com mirrors the same doc pages — use duo.com as the canonical host.

## Current state (2025-26)

Duo remains a Cisco Security product and is increasingly positioned inside Cisco's identity-centric Secure Access (SSE) and ITDR strategy. Cisco Identity Intelligence (ITDR/identity security posture) is delivered via Cisco Security Cloud Control and feeds context to Duo, Cisco Secure Access, and Cisco XDR; it is included with Secure Access subscriptions (standalone CII dashboard separate). Duo Passport (seamless re-auth on trusted devices) and Risk-Based Authentication are the notable recent capabilities, concentrated in Advantage/Premier. Current tier list pricing circa Free/$3/$6/$9 per user/mo; edition feature placement for Trusted Endpoints and Passport has shifted — verify on duo.com/pricing. Note Cisco's 2024 Splunk acquisition strengthens Duo/identity telemetry into Splunk-based SIEM. Confirm current edition matrix before relying on tier specifics.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
