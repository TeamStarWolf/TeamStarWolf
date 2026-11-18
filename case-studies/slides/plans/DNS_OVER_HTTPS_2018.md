# Slide plan: DNS over HTTPS 2018: Encrypting the Lookup, Not the Trust

- Study: case-studies/DNS_OVER_HTTPS_2018.md
- Cover title: DNS over HTTPS 2018 / Encrypting the Lookup / Not the Resolver Trust
- Subtitle: RFC 8484 encrypted DNS queries in transit to a chosen resolver; it did not make browsing anonymous or hide which site is visited.
- Published: 18 November 2026
- Notes: Reference study of a published protocol, not an attributed incident; no live testing performed.

## EXECUTIVE SUMMARY | A transport change, not a promise of anonymity

- RFC 8484 (October 2018) carried DNS queries and responses inside HTTPS exchanges. [1]
- It changed how DNS traffic travelled; the resolver still reads the question to answer it. [1]
- Browser vendors did not all pick the same default resolver model.
- The study separates transport confidentiality, resolver trust, DNS validation and retained visibility.
Caption: Evidence grade: Confirmed standard; a source-based historical study, not a live test.
Notes: Executive-assessment framing from [1]; no packet captures or resolver audits performed.

## KEY FACTS | Dates and a shared port anchor the record

Stat: Oct 2018 | RFC 8484 standardized DoH
Stat: 443 | HTTPS port DoH shares
Stat: Jan 2021 | NSA enterprise DNS guidance
Stat: 1% | Canada rollout starting share
- RFC 8484 is a transport mapping; RFC 9076 (July 2021) sets out the privacy considerations. [1][3]
- DoH runs on HTTPS's usual port 443 and is hard to distinguish from other HTTPS traffic. [10]
- NSA's January 2021 guidance favored encrypted DNS through a designated enterprise resolver. [8]
- Mozilla's July 8, 2021 Canadian rollout with CIRA began at one percent and expanded gradually. [7]
Caption: Evidence grade: Confirmed standards, dated announcements and vendor documentation.
Notes: Dates and port facts from [1][3][7][8][10]; standardized, deployed and default stay distinct.

## PART 1 | What RFC 8484 actually standardized

- It maps a DNS query-response pair to an HTTP exchange, supporting GET and POST. [1]
- It defines the binary application/dns-message representation. [1]
- The client uses a configured URI template, not arbitrary unsolicited endpoints, as its resolver. [1]
- DNS becomes an application carried over HTTPS, which also imports HTTP behavior into DNS handling.
Caption: Evidence grade: Confirmed standard (RFC 8484).
Notes: Transport-mapping scope and server-selection detail from [1]; namespace and recursion unchanged.

## PART 1 | Wire format and provider APIs are different layers

- Google's RFC 8484 API (GET and POST) is distinct from its separate JSON API (GET). [2]
- In the standards POST case the body carries a binary DNS message. [2]
- An HTTP 200 can still wrap a DNS response code that reports failure, so callers must inspect it. [2]
- Minimizing extra HTTP headers matters because they can reveal client characteristics. [2]
Caption: Evidence grade: Confirmed provider documentation.
Notes: API split, error handling and header caution from [2]; not every JSON endpoint is RFC 8484.

## PART 1 | HTTP integration creates additional state

- The spec ties HTTP cache freshness to DNS time-to-live and a response's HTTP Age. [1]
- Freshness must survive translation between two caching systems.
- An answer does not become permanently valid because it arrived over authenticated HTTPS.
- Retained reuse state can also create linkage, a privacy question separate from correctness.
Caption: Evidence grade: Confirmed standard; caching interoperability not benchmarked.
Notes: Cache-freshness and Age handling from [1]; no GET versus POST performance claim made.

## PART 2 | Privacy on the wire is not privacy from the resolver

Left: DoH protects
- The DNS query content and its transport from a nearby on-path observer. [3]
- The integrity of that question on its path to the selected resolver. [1]
Right: DoH does not hide
- The destination IP, and commonly the TLS SNI, still reveal which site is visited. [3]
- The chosen resolver still sees every query it is asked to answer. [3]
Caption: Evidence grade: Confirmed (RFC 9076); boundary described, not measured.
Notes: Traffic-size, timing and resolver-visibility points from [3]; DoH is not a VPN or anonymity tool. [3]

## PART 2 | Firefox's US rollout selected a resolver policy

- Mozilla's February 25, 2020 announcement began a by-default rollout for US users. [4]
- It named Cloudflare as the default provider and offered NextDNS as an alternative. [4]
- It did not announce a simultaneous worldwide default rollout. [4]
- Its Trusted Recursive Resolver program set contractual limits on retention and data use. [5]
Caption: Evidence grade: Confirmed dated announcement and policy.
Notes: Region, staging and provider from [4]; resolver-program contract rationale from [5].

## PART 2 | Chrome described an upgrade of the existing provider

- Google's May 19, 2020 announcement described Secure DNS upgrading to DoH when the provider supported it. [6]
- Users could select another provider or disable the feature. [6]
- This differs from Firefox's stated default-provider model; both still use DoH. [6]
- So not every browser DoH deployment sends every query to one new company.
Caption: Evidence grade: Confirmed dated announcement; current defaults may differ.
Notes: Existing-provider upgrade model from [6]; comparison bounded to the dated sources.

## PART 2 | Canada's staged rollout showed regional variation

- On July 8, 2021 Mozilla announced a Canadian rollout with CIRA, starting at one percent. [7]
- CIRA participated in the Trusted Recursive Resolver program; alternatives were described. [7]
- A planned progression to full coverage is not proof every eligible client was enrolled. [7]
- Region, provider partnership and rollout stage all shaped the deployment.
Caption: Evidence grade: Confirmed plan and partner; not an audit of retention.
Notes: Staged Canadian rollout and partner from [7]; stated policy is not a verified measurement.

## PART 2 | Enterprise guidance framed it as resolver control

- NSA's January 2021 guidance supported encrypted DNS through a designated enterprise resolver. [8]
- Uncontrolled external resolution could bypass protective DNS and expose internal names. [8]
- Its preferred architecture kept the selected resolver and added encryption. [8]
- A browser's independent resolver can produce a different view of names from the operating system's.
Caption: Evidence grade: Confirmed guidance (NSA, January 2021).
Notes: Designated-resolver recommendation and internal-name risk from [8]; a managed path, not a block.

## PART 2 | DNSSEC and DoH answer different questions

- Microsoft's documentation distinguishes DNS encryption on the wire from DNSSEC data validation. [9]
- DoH protects traffic; DNSSEC cryptographically validates the DNS answer's provenance. [9]
- A protected first leg does not prove encryption through every upstream resolver and server. [9]
- An authenticated resolver connection is not the same as a validated signed answer.
Caption: Evidence grade: Confirmed later documentation; not dated to 2018.
Notes: Encryption-versus-DNSSEC distinction and upstream caveat from [9]; the two can complement.

## PART 2 | Port sharing is not invisibility

- Cloudflare documents DoH on HTTPS's usual port 443, hard to distinguish from other HTTPS. [10]
- Difficult to distinguish does not mean undetectable.
- Endpoint identity, connection metadata and client configuration can remain observable. [10]
- The same ambiguity aids privacy and complicates network administration.
Caption: Evidence grade: Confirmed later documentation; no classifier tested.
Notes: Port 443 and transport-ambiguity points from [10]; no evasion rate claimed.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- Reading DoH as anonymity or as a VPN.
- Treating a published RFC or an announcement as universal deployment.
- Assuming all DoH sends every query to one new provider.
Right: Easy to understate
- Removing a nearby observer's plaintext DNS view is a real gain.
- Resolver choice and governance shape the actual privacy outcome.
- Enterprises can lose a monitoring channel they relied on.
Caption: Evidence grade: Mixed; each claim bounded to its source.
Notes: Contrasts drawn across [1][3][4][6][8]; keep standardized, deployed and default distinct.

## CLOSE | Name the protected path, not a blanket promise

- DoH made encrypted DNS accessible through widely implemented HTTPS facilities.
- It did not pick a universal resolver, remove resolver visibility, validate every answer or encrypt later traffic.
- The deployment choices, trusted providers, provider upgrades, regional partners and managed resolvers, decide the outcome.
- Keep standardized, deployed and default-in-a-browser as three distinct milestones.
Caption: Evidence grade: Conclusion synthesis, bounded to the sources.
Notes: Conclusion from [1] through [10]; a source-based historical study awaiting editorial review.
