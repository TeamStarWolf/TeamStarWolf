# Cisco Duo

Cisco Duo is a multi-factor authentication and device trust service. It verifies a second factor at sign-in and checks the health of the device requesting access. It fronts applications, VPNs, and identity providers.

## What it is and where it fits

Duo adds a verification step after a primary credential is accepted. The application or identity provider hands off to Duo, which confirms the user with a second factor and evaluates the device. Access proceeds only when both checks pass.

For an identity and security team, Duo is the enforcement point for multi-factor authentication and device trust across a mixed estate. It works with applications that have no native strong-authentication support. It also layers device posture onto the sign-in decision.

A licence tier decides which capabilities are in force. Device trust, Trusted Endpoints, and richer policy require higher tiers. Confirm the tier before relying on a given control.

## Architecture and how it works

Duo inserts itself into the authentication flow. The protected resource integrates through an application connector, a web gateway, or federation. After the primary factor is accepted, the resource calls Duo before completing the session.

The user approves the second factor through the Duo mobile application, a passkey, or a hardware token. For device trust, Duo reads the posture of the endpoint and compares it to policy. The decision returns to the resource, which then grants or denies access.

Policy is layered. A global policy sets a baseline, and application-level and group-level policies refine it. Adaptive policy adjusts requirements based on signals such as network location and device state.

## Key capabilities

- Multi-factor authentication through push approval, passkeys, and hardware tokens.
- Trusted Endpoints, which distinguishes managed devices from unmanaged ones and gates access accordingly.
- Device health policy that blocks sign-in from out-of-date operating systems and browsers.
- Adaptive policies that vary the requirement by user, group, application, and risk signal.
- Single sign-on so one authentication reaches multiple downstream applications.
- Reporting on authentication attempts, denied sign-ins, and device posture.

## Deployment and operations

Duo is a cloud service. Integration is through application connectors, an authentication proxy for on-premises and network devices, and federation with an identity provider. Each protected application is onboarded and assigned a policy.

Rollout is staged. A pilot group enrolls first, policy is tuned against real sign-in data, and enforcement widens once support load and failure modes are understood. Enrollment and recovery procedures are defined before broad rollout.

Operations teams monitor authentication logs for denied attempts and anomalies. They review device health failures to guide endpoint remediation. Help-desk procedures for lost devices and account recovery are documented and access-controlled.

## Integrations and data flow

Duo protects web applications, VPN and remote-access gateways, and server logins. The authentication proxy extends coverage to network devices and legacy systems that speak RADIUS or LDAP.

Duo integrates with Entra ID and other identity providers. It can act as the second factor behind a provider's primary authentication, or provide single sign-on itself. See `/platforms/entra-id.md` for the upstream identity provider.

Authentication and device-posture events flow out to monitoring and SIEM platforms for correlation with other security signals. Device inventory signals can align with endpoint management data.

## Hardening and secure use

Prefer phishing-resistant factors over push where possible. Passkeys and hardware security keys resist push-fatigue and real-time phishing in a way that simple approval prompts do not.

Restrict administrative access with role-based access control. Separate full administrators from read-only and help-desk roles so day-to-day tasks do not require the highest privilege.

Protect API credentials used by Duo integrations. Integration keys and secret keys are credentials. Hardcoding or exposing them maps to CWE-798 Use of Hard-coded Credentials. Store them in a secrets manager, scope them narrowly, and rotate them.

Design policy so multi-factor authentication is enforced exactly once and cannot be bypassed by a second path. An application reachable through both a protected and an unprotected route defeats the control. Inventory every access path and ensure each enforces the factor.

## Where it fits in the program

Duo is the step-up and device-trust layer in front of applications and remote access. It raises the cost of credential theft, because a stolen password alone does not complete a sign-in.

Its denied-authentication and device-health data feed detection and endpoint remediation. A spike in denied push approvals can signal an active attack and is an input to incident response.

## Resources

- Cisco Duo documentation
- Cisco Duo Administrator Guide
- Cisco Duo Trusted Endpoints documentation
- Cisco Duo Authentication Proxy documentation

## Related pages

- `/platforms/README.md`
- `/VULNERABILITY_MANAGEMENT_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/entra-id.md`
- `/platforms/cyberark.md`
