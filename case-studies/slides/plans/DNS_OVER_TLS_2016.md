# Slide plan: DNS over TLS 2016: Authentication and Fallback Limits

- Study: case-studies/DNS_OVER_TLS_2016.md
- Cover title: DNS over TLS 2016 / Encrypting the Query / Not the Destination
- Subtitle: RFC 7858 gave DNS a dedicated TLS port and authentication, but it protects only the client-to-resolver hop and does not hide the site you visit.
- Published: 18 November 2026
- Notes: Reference study of a protocol, not an incident; no victims, no exploit code, no deployment measurement claimed.

## EXECUTIVE SUMMARY | Encryption added is not a complete privacy service

- DNS over TLS shows that adding encryption is not the same as defining a complete privacy service.
- The core distinction is attempting encryption versus requiring an authenticated encrypted connection.
- A product can support DoT without guaranteeing that every lookup is protected.
- A strict client may refuse to resolve when the secure service is unavailable; that can be the intended outcome.
Caption: Evidence grade: A protocol reference study, not an incident to attribute.
Notes: Executive-assessment framing; chronology rests on [1][2][4][5], with no deployment measurement.

## KEY FACTS | A standards chronology, not a deployment count

Stat: May 2016 | RFC 7858 transport specification
Stat: Mar 2018 | RFC 8310 Strict and Opportunistic
Stat: Jan 2019 | Google Public DNS DoT launch
Stat: Port 853 | Dedicated TLS port, no cleartext
- RFC 7858 uses TCP port 853 and begins with a TLS handshake; cleartext is prohibited on that connection.
- The study examines selected standards and vendor evidence, not an exhaustive implementation audit.
- A publication date is neither an installation count nor proof a device's resolver used the protocol.
- Keep standard published, deployed and default as three distinct conditions.
Caption: Evidence grade: Confirmed dated standards and announcements.
Notes: Port and prohibition facts from [1]; dates from [2][5]; scope caution from the executive assessment.

## PART 1 | The 2016 boundary was a dedicated encrypted port

- RFC 7858 covers the stub-resolver to recursive-resolver path, with TCP port 853 by default.
- An earlier STARTTLS-style upgrade approach was removed; the dedicated port marks encrypted service.
- Inside the connection, DNS messages keep a two-byte length prefix and can be pipelined.
- Replies can arrive out of order and must be matched to the correct request.
Caption: Evidence grade: Confirmed specification (RFC 7858).
Notes: Port, upgrade removal and session-management details from [1]; a standard describes a service, not its installation.

## PART 1 | TCP was not merely an emergency fallback

- March 2016's RFC 7766 clarified DNS over TCP before the DoT specification appeared.
- Clients may select TCP without first trying UDP, and may reuse existing connections.
- Connection reuse spreads setup cost; long idle timeouts and limited capacity can exhaust a server.
- Cold, warm, concurrent and reconnect cases are different experiments, not a single benchmark.
Caption: Evidence grade: Confirmed standard (RFC 7766); analytical caution, not a measurement.
Notes: TCP selection, reuse and pipelining from [3]; the experiment distinction is derived from the architecture.

## PART 1 | Authentication changed the meaning of success

RFC 8310 split the service into two profiles with different success criteria.

Left: Strict Privacy
- Requires encryption and successful server authentication.
- Fails closed if that cannot be achieved, and must not silently fall back.
Right: Opportunistic Privacy
- Can yield an authenticated, unauthenticated or cleartext result.
- Depends on available information and client behavior.
Caption: Evidence grade: Confirmed profiles (RFC 8310); the test is conceptual.
Notes: Profiles and the no-silent-fallback rule from [2]; [2] also notes a bootstrap problem: where to connect and whom to trust are separate inputs.

## PART 2 | Android made the strict distinction user-visible

- Google's April 17, 2018 security-blog cross-post described DoT in the Android P Developer Preview.
- The default attempted an upgrade when the network's DNS server supported the protocol.
- A user could set a private provider hostname; failure could mark the network as lacking internet access.
- System resolution and an application's own queries are different paths; a settings screen covers only one.
Caption: Evidence grade: A developer-preview announcement, not shipped device coverage.
Notes: Default behavior, provider hostname and the application-path distinction from [4]; no device assessment was performed.

## PART 2 | Protocol support is not a provider mandate

- On January 9, 2019 Google announced DoT support for Google Public DNS.
- It named TLS 1.3, TCP Fast Open, pipelining and out-of-order responses as overhead-reducing features.
- Supporting a protocol does not mandate one provider or prove any implementation was fastest.
- The post is a provider's account of its own service, not an independent comparison.
Caption: Evidence grade: A provider's own account, not a comparative study.
Notes: Launch date, named features and client compatibility from [5]; transport support stays distinct from resolver selection.

## PART 2 | The privacy boundary extends past the handshake

- Google's DoT documentation records EDNS Client Subnet re-enabled for DoT on June 27, 2019.
- RFC 7871 (May 2016, Informational) describes ECS carrying origin-network information to authoritative servers.
- It recommends ECS stay disabled by default unless operators enable it for a clear benefit.
- Encrypting a message in transit does not decide what the resolver later forwards.
Caption: Evidence grade: Confirmed dated change; no measured user impact.
Notes: The June 27, 2019 ECS note from [6]; ECS motivation and the default-off recommendation from [7]; the boundary includes resolver behavior after decryption.

## PART 2 | Padding addresses a different residual signal

- October 2018's Experimental RFC 8467 discusses policies for the EDNS padding option.
- Padding increases message sizes to make size-based correlation harder, alongside encrypted transport.
- The existence of a mechanism is distinct from how much padding an implementation adds.
- Hiding the literal question and reducing observable message length are different objectives.
Caption: Evidence grade: Experimental RFC 8467; introduction and status only.
Notes: Padding purpose and the mechanism-versus-policy distinction from [8]; detailed block sizes are not prescribed.

## PART 2 | The 2020 guidance widened operator responsibility

- RFC 8932 (October 2020) addresses DNS privacy service operators, not just the wire protocol.
- It recommends automated certificate issuance, renewal and expiration monitoring.
- An authenticated connection does not by itself prove the resolver validated DNSSEC data.
- A TLS proxy can terminate the protected connection before an unencrypted proxy-to-server path.
Caption: Evidence grade: Confirmed operator guidance (RFC 8932).
Notes: Certificate management, the DNSSEC distinction and the proxy boundary from [9]; "TLS enabled" is not a completion criterion.

## PART 2 | The 2021 assessment kept resolver trust

- RFC 9076 (July 2021) examines residual risks beyond the immediate transport.
- It covers correlation by size and timing, resolver visibility and resolver-selection consequences.
- Blocking port 853 can restrict access to encrypted resolution, with effect depending on context.
- Separate what the local network, the chosen resolver and later participants each receive.
Caption: Evidence grade: Confirmed privacy assessment (RFC 9076).
Notes: Residual risks, the port-853 note and divergent application settings from [10]; the study does not promise anonymity.

## PART 2 | A clearly separate 2022 transport development

- On July 19, 2022 Google described adding DNS over HTTP/3 to Android.
- Qualifying Android 11-and-later devices could upgrade transport while keeping the selected DNS service.
- Motivations included reconnection costs, mobile network changes and head-of-line blocking.
- Deploying DoT did not end transport engineering; protocol capability and implementation behavior stay separate.
Caption: Evidence grade: Confirmed later follow-up, not 2016 launch evidence.
Notes: DoH3 announcement and motivations from [11]; its rollout percentages are not reused as a universal performance ranking.

## PART 2 | DoT and DoH are different trade-offs, not ranks

Two encrypted-DNS designs make different visibility trade-offs for a network.

Left: DNS over TLS
- Uses a dedicated TCP port 853, distinct from other traffic.
- A dedicated port is easier for a network to see and to manage or block.
Right: DNS over HTTPS
- Carries DNS inside ordinary HTTPS, blending with web traffic.
- Harder for a network to single out, which shifts the management trade-off.
Caption: Evidence grade: Conceptual trade-off; dedicated-port facts from the record.
Notes: The dedicated port from [1]; port-853 blocking from [10]; neither option is endorsed, and DoH is covered in the related DoH study.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- Reading "DNS became encrypted in 2016" as device-wide deployment.
- Treating a published RFC or a launch post as completed coverage.
- Calling DoT anonymity, when destination IP and resolver trust remain.
Right: Easy to understate
- A standardized encrypted transport with authenticated resolver access.
- Fallback behavior as a central part of the privacy promise.
- Resolver behavior after decryption, such as ECS forwarding.
Caption: Evidence grade: Editorial corrections the record supports.
Notes: Overstated and understated contrasts drawn across [1][4][5][6]; keep published, deployed and default separate.

## CLOSE | Precision beats a single private DNS claim

- A standardized encrypted DNS transport and authenticated resolver access were specific, substantial advances.
- DoT protects the client-to-resolver hop; it does not hide the destination or anonymize browsing.
- Keep standard published, deployed and default distinct, and do not collapse availability into privacy.
- A successful lookup, an encrypted connection and an authenticated provider are related but different observations.
Caption: Evidence grade: Case-specific conclusions, bounded to the sources.
Notes: Conclusion synthesis across the study; rests on [1] through [11], with fallback behavior central to the privacy promise.
