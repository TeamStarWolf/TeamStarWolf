# PHP2Shell and the October 2026 Attack Wave: A Case Study

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · House intelligence: [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) · Related: [eMudhra CA Key Compromise](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)

## Executive summary

October 2026 compressed several years' worth of trust failures into a few weeks. The centerpiece was PHP2Shell: two pre-authentication remote-code-execution flaws in PHP itself (CVE-2026-109618 and CVE-2026-109619), disclosed on 20–21 October and exploited at internet scale within the hour. Around it, three trust layers failed in roughly 72 hours (the web runtime, the Web PKI, and the software and SaaS supply chain), the largest cryptocurrency theft in history drained about $6.3 billion from Binance, a trojanized build of an AI coding extension planted SSH backdoors on developer machines, and a dense cluster of Japanese consumer breaches ran in parallel. Agentic AI appeared on both sides of the ledger, as an attacker accelerant and as a target.

Evidence grade: **Confirmed** overall (vendor, government and primary-research sources for each major item; single-source or claimed figures are marked below).

### Key findings

- **PHP2Shell put every PHP web server in scope.** Two memory-corruption bugs in PHP core (a use-after-free in the upload-progress feature and a partial-initialization fault under memory pressure) allow unauthenticated RCE. They affect PHP 5.4 through 8.5 and were fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35.
- **Exploitation beat disclosure.** Amazon's MadPot sensors saw attempts on 17 October, four days before the public advisory. Cloudflare measured tens of thousands of attempts within 45 minutes of disclosure, rising to millions. Payloads included a Mirai fork and web-shell drops; as of CISA's advisory, no successful compromise had been confirmed.
- **Supply chain and SaaS identity were the dominant vector.** Microsoft attributed the ConnectWise Cloud Backup compromise to China-aligned Storm-0940, which abused a stolen OAuth application credential to reach Microsoft 365 tenants at about 2,900 sign-ins a minute using the agentic-AI pentest framework ARTEX. A trojanized LiteLLM 1.107.0 reached PyPI and container registries after a master key leaked months earlier and was never rotated.
- **The record Binance heist was North Korean.** The FBI attributed the theft of more than $6 billion in virtual assets on 29 October to the actor it tracks as TraderTraitor; Binance put the figure at about $6.3 billion, most of it moved in roughly 20 minutes, with around $3 billion in stablecoins later frozen.
- **AI was both weapon and target.** Storm-0940 used ARTEX to speed the ConnectWise intrusion, while a trojanized "Claude Code" extension in the Cursor marketplace and the poisoned LiteLLM package attacked the AI toolchain itself.

### Top recommendations

1. Patch PHP now to a fixed release and inventory every PHP surface, including appliances and bundled interpreters; a WAF rule is a stopgap, not a fix.
2. Treat SaaS application credentials (OAuth app secrets, API keys) as privileged identities: rotate on any provider incident, scope tightly, and alert on high-rate non-interactive sign-ins.
3. Govern AI developer tooling like any other supply-chain dependency: pin versions, verify publisher and marketplace integrity, and watch for persistence (SSH keys, reverse tunnels) that survives uninstall.
4. Keep a software bill of materials and rotate leaked keys on disclosure, not on a schedule; the LiteLLM compromise turned an un-revoked May key into an October incident.

## Scope and method

This study covers PHP2Shell and the broader October 2026 incident wave, from vendor, government and primary-research sources, cross-checked against the [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) weekly report for 2026-W43. Each claim carries one of three evidence grades.

| Grade | Meaning |
|---|---|
| Confirmed | A vendor, CISA KEV, government agency, or the primary research team confirms the exploitation or compromise |
| Reported | Attempts or claims exist, but no primary source confirms a successful compromise |
| Demonstrated | A research reconstruction with no known in-the-wild use |

## Part 1: PHP2Shell (CVE-2026-109618, CVE-2026-109619)

PHP2Shell is the name researchers gave to two critical flaws in PHP core, each rated CVSS v4.0 9.2 (**Confirmed**: PHP project advisory). Both can give unauthenticated remote code execution to any PHP installation serving web requests.

- **CVE-2026-109619**: a use-after-free in PHP core's upload-progress feature.
- **CVE-2026-109618**: memory corruption when an out-of-memory condition interrupts PHP while internal request data is only partially initialized.

The flaws affect PHP 5.4 through 8.5, which is effectively the entire supported and legacy range, and were fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35, released 20–21 October 2026. CISA, NSA and NCSC-UK told organizations to patch or take PHP servers offline (**Confirmed**).

The timeline is the lesson. Amazon Threat Intelligence observed exploitation attempts in its MadPot honeypots on 17 October, four days before public disclosure (**Confirmed**: Amazon). watchTowr reported in-the-wild exploitation of both CVEs (**Reported**). Cloudflare measured tens of thousands of attempts within about 45 minutes of the announcement, climbing to millions by 22 October (**Confirmed**: Cloudflare telemetry). Observed payloads included a Mirai botnet fork (Nokia Deepfield) and attempts to drop a web shell through a server-side session file from a China-based address (**Reported**). As of CISA's advisory, no successful compromise had been confirmed, which separates mass scanning from mass breach.

### PHP2Shell remediation

| Surface | How to remediate |
|---|---|
| PHP runtime | Upgrade to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later; distributions have backported the fix, so check the package, not only the banner (`php -v`, `dpkg -l php*` or `rpm -q php`) |
| Web servers | Patch the PHP that each server embeds: mod_php, PHP-FPM, and any interpreter bundled in an appliance or container image; restart the service after patching |
| Containers / CI | Rebuild images from patched base packages, pin by digest, redeploy, and scan images and SBOMs for vulnerable PHP versions |
| Appliances and products | Many vendor products embed PHP; apply the vendor's PHP2Shell advisory rather than assuming the OS patch covers it |
| Interim only | A WAF or mod_security rule can blunt the public payloads but does not close the memory-corruption flaw; treat it as time bought, not a fix |

## Part 2: three trust layers in 72 hours

The Intelligence Hub's 2026-W43 report frames the week of 19–25 October as three distinct trust layers failing almost at once.

1. **The web runtime.** PHP2Shell, above.
2. **The Web PKI.** Eight eMudhra (emSign) intermediate CA private keys were generated with almost no entropy, one effectively the integer 4, and browser and OS vendors distrusted them on 20–21 October; eMudhra then announced it would leave the TLS business. This has its own full write-up in [The eMudhra Certificate Authority Key Compromise](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md) (**Confirmed**).
3. **The software and SaaS supply chain.** Microsoft attributed the ConnectWise Cloud Backup compromise to Storm-0940 (**Confirmed**: Microsoft). A stolen OAuth application credential let the actor sign into customer Microsoft 365 tenants at about 2,900 attempts a minute, with no interactive login, using the agentic-AI pentest framework ARTEX; ConnectWise identified the issue on 14 October and suspended the service on 17 October, and says the stored backups themselves were not accessed. In parallel, LiteLLM 1.107.0 was trojanized on PyPI and in container registries after a master key that leaked in May was never revoked (**Confirmed**).

Alongside these, CISA added eight CVEs to its Known Exploited Vulnerabilities catalog that week (Plex, SiteGuard, Siemens Software Center, Arista VeloCloud Orchestrator, and Collabora CODE), none flagged for known ransomware use, and CISA and the FBI issued a #StopRansomware advisory on the SafePay group (**Confirmed**).

## Part 3: the wider October landscape

- **Binance, the largest crypto heist on record (29 October).** The FBI attributed the theft of more than $6 billion to North Korea's TraderTraitor; Binance stated about $6.3 billion, most of it laundered in roughly 20 minutes, with around $3 billion in stablecoins frozen (**Confirmed**: FBI alert, Binance, Chainalysis and TRM analysis).
- **A trojanized AI coding extension (29 October).** Malicious builds 2.1.312 and 2.1.313 of a "Claude Code" extension sat in the Cursor marketplace for about 11 hours, planting an attacker SSH key and a reverse tunnel that survived uninstalling the extension; up to 5,000 users were exposed. The builds were not produced by Anthropic, and Cursor rebuilt its marketplace in response (**Confirmed**: Sophos, Microsoft, Cursor). A claim that the upload followed a breach at Anthropic is an unverified allegation (**Reported**).
- **A cluster of Japanese breaches.** Sony's So-net and plala disclosed 2,585,481 exposed records (**Confirmed**); Burger King Japan disclosed about 11.18 million app records accessed between 2 and 7 October (**Confirmed**); Japanese cloud provider IDC Frontier's IDCF Cloud was disrupted by ransomware on 7–8 October, affecting 495 organizations (the 3.6 PB "encrypted" figure is an attacker claim, **Reported**); Advantest, Japan Airlines (about 90,000 passengers via a third party), and GMO were also hit (**Confirmed** / **Reported** by source).
- **Other notable items.** A Florida financial-aid site breach exposed Social Security numbers for about 4.9 million people (**Reported**); ASOS confirmed a customer-data breach (**Confirmed**); the GlassWorm campaign abused OVHcloud GitHub infrastructure, and the Railway platform reported a supply-chain incident (**Reported**).

## Cross-cutting themes

- **The supply chain was the main battlefield.** PHP2Shell (a shared runtime), eMudhra (shared trust roots), ConnectWise (shared SaaS identity), LiteLLM and the Claude Code extension (shared developer tooling) all turned one compromise into many victims.
- **Agentic AI is on both sides.** Storm-0940 used ARTEX to move faster than human-paced response; the AI toolchain itself (the extension, LiteLLM) was a target. Treat AI-assisted intrusion speed as a planning assumption.
- **Speed is the defining metric.** PHP2Shell went from disclosure to millions of exploit attempts in hours, and the Binance funds moved in about 20 minutes. Containment that waits for human approval loses this race.
- **Identity and keys are the soft center.** The ConnectWise OAuth secret and the un-rotated LiteLLM master key each converted a stored credential into a breach; key rotation on disclosure is not optional.

## Sources

- PHP project security advisory and release notes for 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; Amazon Threat Intelligence (MadPot), Cloudflare, watchTowr, Akamai, Qualys and Arctic Wolf analyses of PHP2Shell.
- Microsoft and ConnectWise advisories on the Cloud Backup compromise and Storm-0940; the LiteLLM project and PyPI advisories.
- The FBI alert on the Binance theft, with Binance, Chainalysis and TRM analysis, and reporting from Al Jazeera, NPR and BleepingComputer.
- Sophos, Microsoft and Cursor on the trojanized Claude Code extension; company disclosures for the Sony So-net, Burger King Japan, IDC Frontier, Japan Airlines and ASOS breaches.
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) weekly report 2026-W43, which cross-references these items to their primary sources.

## Related references

- [The eMudhra Certificate Authority Key Compromise](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md)
- [The XZ Utils Backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md)
- [AI Threats: a 2026 Case Study](/case-studies/AI_THREATS_2026.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
