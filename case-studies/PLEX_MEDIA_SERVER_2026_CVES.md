# Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab

*A TeamStarWolf case study. Published 4 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services](/INTERNET_FACING_SERVICES_REFERENCE.md), [Container Security](/CONTAINER_SECURITY_REFERENCE.md), [Homelab Setup](/HOMELAB_SETUP.md), [Triage a CVE](/guides/TRIAGE_A_CVE.md), [PHP2Shell, October 2026](/case-studies/PHP2SHELL_OCTOBER_2026.md), [Log4Shell](/case-studies/LOG4SHELL.md), [Ghostcat](/case-studies/GHOSTCAT_CVE_2020_1938.md), [ProFTPD mod_copy](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md), [Magento PolyShell](/case-studies/MAGENTO_CVE_2026_48356.md), [Node.js Brotli](/case-studies/NODEJS_CVE_2026_111497.md), [PHP 8.4.27](/case-studies/PHP_8_4_27_CVES.md), [Collabora CODE in Nextcloud](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management leads, self-hosters and home-lab owners who run Plex Media Server, incident responders and security engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 34 min (7,922 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run Plex Media Server or allow it on your network, you need the facts of the Plex2Shell chain (CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656), or you want to find, fix and triage it on your own hosts

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 4: what the lab showed](#part-4-what-the-lab-showed), [Part 5: find it and fix it on real hosts](#part-5-find-it-and-fix-it-on-real-hosts)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[CVE Reference](/CVE_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [PHP2Shell and the October 2026 Attack Wave](/case-studies/PHP2SHELL_OCTOBER_2026.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

If you run Plex Media Server for yourself, your family or your friends, and you ever turned on Remote Access or forwarded port 32400, this study is about your server. Four flaws in Plex Media Server before 1.43.3.10861, each rated Medium or High on its own, chain into code execution by an unauthenticated remote attacker with the privileges of the server process (**Confirmed**: Plex) [9]. The researcher who found them, Zach Main, calls the chain Plex2Shell and rates it 9.8 Critical [12]. Plex shipped the fixed build on 4 August 2026 [10]. The details went public on 16 October 2026, attacks on a honeypot began the next morning [14], and by 19 October Plex was describing the flaws as actively and widely exploited, with compromised servers running cryptocurrency miners and proxy software [9]. CISA added all four to the Known Exploited Vulnerabilities catalog on 20 October 2026 [7].

This study is lab-backed, and the lab run was deliberately narrow. On 4 November 2026 UTC a lab host ran official `plexinc/pms-docker` images in matched pairs, a vulnerable build beside the fixed 1.43.3.10861, on loopback only. No exploit step ran: no request reached any endpoint in the chain [38] [39] [40] [41]. What the lab shows is how to find a vulnerable server and prove the fix, and it turned up three practical traps. A host package check returned nothing while two Plex servers ran in containers. A naive version parser read the XML declaration's `version="1.0"` and labelled the fixed build vulnerable. And the vendor's own advisory title can make 1.43.3.10828, the last vulnerable build, look safe (**Demonstrated** for the first two; **Inferred** for the third) [38] [39] [9].

Evidence grade: the four vulnerabilities, the fixed build and the KEV listing are **Confirmed**; the chain mechanics are **Confirmed** from the researcher's own write-up; press coverage of the attacks is **Reported**; the lab's version checks, baselines and fix verification are **Demonstrated**.

### Key facts at a glance

| Field | Value |
|---|---|
| Product | Plex Media Server (PMS) on Windows, macOS, Linux, NAS, Docker and NVIDIA Shield, the platforms the vendor's update steps cover; the official Docker image is `plexinc/pms-docker` [5] [9] [22] |
| Identifiers | CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656; GitHub advisories GHSA-5p7w-r379-3c2m, GHSA-3j7c-jr86-m5jq, GHSA-9x88-w2p7-56vh and GHSA-2g2v-9wf5-6m3g [5] [8] |
| Researcher name | Plex2Shell (Zach Main, credited in every CVE record) [5] [12] |
| Weaknesses | CWE-918 (-96652, -96655), CWE-84 (-96654), CWE-73 (-96656) [1] [2] [3] [4] |
| Scores | Individually CVSS 3.1 4.3, 6.5, 4.3 and 7.2 (CISA as CNA); the researcher rates the full chain 9.8 Critical, PR:N [1] [2] [3] [4] [12] |
| Affected | Every build before 1.43.3.10861, including 1.43.3.10828 [5] [6] [9] |
| Fixed | 1.43.3.10861, general release 4 August 2026 (Beta 3 August) [10] [6] |
| Disclosure | Reported to Plex 27 July 2026; CVEs published 23 September 2026; write-up public 16 October 2026 [12] [5] |
| Exploitation | First seen on a honeypot 17 October 2026; vendor reports wide exploitation; in CISA KEV since 20 October 2026 [14] [9] [7] |
| Payloads seen | Cryptocurrency miners and proxyware (`mylovelyminer`, `x12345`, `myawesomeproxy`); no named group, ransomware use Unknown [9] [7] |
| KEV due dates | 23 October 2026 (-96654, -96656) and 3 November 2026 (-96652, -96655); forensic triage flagged for -96656 [7] |
| Lab result | Version exposure and fix verified on 1.43.2.10687 and 1.43.3.10828 against 1.43.3.10861; no exploit step run (**Demonstrated**) [38] [39] [40] [41] |
| Workaround | Turn off Remote Access if you do not need it; do not forward 32400 directly [9] |

### Key findings

- **Four modest bugs make one critical chain.** On their own the four CVEs score Medium or High, and three carry a privilege requirement in their vectors (Low for -96652 and -96655, High for -96656), although -96652's record says any token value is accepted. Chained, they need nothing: a timeline request that checks only that a token header exists, a loopback-only plugin API with a broken input guard, an owner-token leak through a prefix match on `http://127.0.0.1`, and a transcoder option that writes a shared object into the Codecs folder, which the transcoder then loads (**Confirmed**: researcher) [12].
- **The fix was out for ten weeks before the details.** 1.43.3.10861 reached general release on 4 August 2026, the day Plex acknowledged the report [10] [12]. Plex announced the security update on 1 September and the CVEs followed on 23 September [9] [5]. Exploitation followed the public write-up of 16 October by about a day [14].
- **The version line is 1.43.3.10861, not 1.43.3.** The vendor's advisory title says "v1.43.2 and earlier" and its first post asks for "1.43.3 or newer" [9]. Every CVE record, the CISA advisory and Plex's own October update put the fixed line at 1.43.3.10861, so 1.43.3.10828 is vulnerable (**Inferred** from the Confirmed records) [5] [6] [9]. NVD's "Release Notes" reference points at the 1.43.3.10828 release post, which lists no security fixes [10].
- **The primaries disagree on which CVE is which step.** Plex's CVE table maps CVE-2026-96655 to disclosure of the owner's admin token. NVD, the CISA advisory and KEV describe it as an authenticated SSRF in `/video/:/transcode/universal`. The proof-of-concept README maps it differently again (**Confirmed** disagreement) [9] [3] [6] [7] [13]. This study uses the CVE record wording, because CISA is the CNA.
- **The lab found the blind spot in a package check.** On a Docker-only host, `dpkg-query` and `rpm -q` reported no Plex package while two Plex servers were listening (**Demonstrated**) [38].
- **The lab found the trap in a version parser.** A check that grepped every `version="..."` attribute from `/identity` picked up the XML declaration, `version="1.0"`, and labelled the fixed 1.43.3.10861 build vulnerable. The corrected parse reads only the MediaContainer attribute (**Demonstrated**) [38] [39].
- **Patching is not the end state for an exposed server.** KEV flags CVE-2026-96656 for forensic triage, and Plex says any internet-reachable server older than 1.43.3.10861 should be assumed possibly compromised [7] [9].

### Top recommendations

1. Update every Plex Media Server to 1.43.3.10861 or later, and check the full build number, not just "1.43.3" [9] [5].
2. Inventory Plex in containers as well as packages: look for `plexinc/pms-docker` images and tags, not just `plexmediaserver` packages (**Demonstrated** gap) [38].
3. If a server older than 1.43.3.10861 was reachable from the internet, treat it as possibly compromised: rebuild from a clean install, empty the Codecs folder, check the transcoder options in the server preferences, sign out all devices and change the Plex password [9].
4. Turn off Remote Access where you do not need it and stop forwarding port 32400 directly [9].
5. Hunt for the vendor's indicators: processes named `myawesomeproxy`, `mylovelyminer` or `x12345` started by Plex, unfamiliar `.so` or `.dll` files in Codecs, outbound connections to `proxystream.st`, and high CPU while nothing plays [9].

## Scope and method

This study covers the four Plex Media Server CVEs that CISA lists as chainable, from the private report on 27 July 2026 to the lab run on 4 November 2026 UTC. A fifth bug fixed in the same build, CVE-2026-96651, is noted but is not part of the chain [6]. Every source in the Sources table was opened on 4 November 2026. The public proof-of-concept repository is recorded by name and metadata only; its code was not opened, copied or run [13].

| Grade | Meaning |
|---|---|
| Confirmed | A primary source was opened: the CVE record, NVD, CISA, the vendor, the researcher's own write-up, or a first-hand observation by the person who made it |
| Reported | A secondary source's account, not independently corroborated (press coverage) |
| Demonstrated | Shown in this study's lab run; the capture file is named |
| Inferred | The study's reasoning from the record and the lab, labelled where it appears |

Exploit-class steps are described in one sentence and never quoted or shown. The lab ran none. Version checks, baselines and the observables that differ between the vulnerable and fixed builds are quoted from the captures.

## Part 1: the four flaws

### What each CVE is

Each record lists Plex Media Server as affected below 1.43.3.10861 and unaffected at 1.43.3.10861 [5]. CISA assigned all four as the CNA, and NVD shows the CNA scores as Secondary (**Confirmed**) [1] [2] [3] [4] [5].

| CVE | Weakness | What the record says | CVSS 3.1 | CVSS 4.0 | Privileges in the vector |
|---|---|---|---|---|---|
| CVE-2026-96652 | CWE-918 Server-Side Request Forgery | SSRF via `/player/timeline`: any `X-Plex-Token` value is accepted, and a full URL in the `protocol` parameter makes the server POST to a destination the attacker picks | 4.3 Medium | 5.3 Medium | Low |
| CVE-2026-96654 | CWE-84 Improper Neutralization of Encoded URI Schemes in a Web Page | URL values in `searchOne` are not neutralized, so an attacker can call other plugins' functions with their own parameters | 6.5 Medium | 6.9 Medium | None |
| CVE-2026-96655 | CWE-918 Server-Side Request Forgery | An authenticated user can make the server request arbitrary internal or external addresses through the `/video/:/transcode/universal` path parameter | 4.3 Medium | 5.3 Medium | Low |
| CVE-2026-96656 | CWE-73 External Control of File Name or Path | An admin can write arbitrary files that may run on load: `TranscoderH264Options` is appended verbatim to x264's option string, and at startup every `.so` file is loaded with no signature, execute-bit or symbol check | 7.2 High | 8.6 High | High |

Sources: [1] [2] [3] [4]. The full CVSS 3.1 vectors are `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` for -96652 and -96655, `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` for -96654 and `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` for -96656 [1] [2] [3] [4].

The CVE-2026-96652 vector says Low privileges while its description says any token value is accepted. Both are in the record; the researcher's account explains the gap: the endpoint checks that a token header is present, not that it is valid [1] [12].

### How the four chain

The researcher's write-up of 16 October 2026 describes five stages (**Confirmed**: researcher) [12]:

1. **A forged request from the server.** The timeline endpoint checks only that a token header exists, and a full URL in its `protocol` parameter makes the server POST to a destination the attacker picks [1] [12]. In the chain, that destination is the server's own loopback interface.
2. **A loopback-only API that trusts loopback.** The `/system/agents/*` API opens without a token on loopback. The identifier guard in `searchOne` is dead code, and the identifier is spliced unencoded into an internal URL, which lets a forged call reach another plugin's function.
3. **An owner-token leak.** The plugin framework attaches the server owner's token to any URL that merely starts with `http://127.0.0.1`. A lookalike hostname that begins that way but resolves elsewhere (the write-up names `sslip.io` names) receives the token.
4. **A file write into Codecs.** With the owner token, the attacker sets the transcoder's x264 options so that the transcoder writes a file into the Codecs folder. The transcoder fetches the media from a remote host with no host allowlist.
5. **An unsigned load.** The transcoder loads the `.so` from the Codecs folder with no signature check, and the code runs as the `plex` user.

The researcher rates the full chain CVSS 3.1 9.8 Critical (`PR:N`) [12]. No CVSS record scores the chain itself. Plex's October update says the same thing in plain terms: chained, the issues let an unauthenticated remote attacker run code with the privileges of the server process (**Confirmed**: Plex) [9].

The researcher says large language models were used heavily in a recon, hunt, verify and chain workflow, and that the judgement calls on what to look for and what to prioritize were the researcher's own (**Confirmed** as the researcher's account of their own method) [12].

### The fifth bug in the same build

The CISA advisory VA-26-266-01 lists five Plex CVEs fixed in 1.43.3.10861. The fifth, CVE-2026-96651, is a path traversal (CWE-22) through `/system/agents/media/get`, CVSS 3.1 6.5. It is not in KEV and is not part of the Plex2Shell chain (**Confirmed**) [6] [7].

## Part 2: the public record

### Timeline

| Date | Event | Source | Grade |
|---|---|---|---|
| 2026-05-19 | Docker tag `1.43.2.10687-563d026ea` pushed (a vulnerable build used in the lab) | [11] | Confirmed |
| 2026-07-14 | 1.43.3.10828 general release, the last vulnerable 1.43.3 build; its notes list no security fixes; Docker tag pushed the same day | [10] [11] | Confirmed |
| 2026-07-27 | Zach Main reports the chain to Plex | [12] | Confirmed |
| 2026-08-03 | 1.43.3.10861 Beta; the CISA advisory gives this as each CVE's release date | [10] [6] | Confirmed |
| 2026-08-04 | 1.43.3.10861 general release and Docker tag; Plex acknowledges the report and pays a bounty | [10] [11] [12] | Confirmed |
| 2026-09-01 | Plex announces the security update, asks owners to update to "1.43.3 or newer", and says CVEs have been requested | [9] | Confirmed |
| 2026-09-23 | CISA, as CNA, reserves and publishes the four CVEs; CISA advisory VA-26-266-01; NVD and GitHub advisories published | [5] [6] [1] [8] | Confirmed |
| 2026-10-16 | The researcher's Plex2Shell write-up goes public; Plex dates the public PoC to the same day | [12] [9] | Confirmed |
| 2026-10-17 | A honeypot operator sees the first in-the-wild exploitation, that morning | [14] | Confirmed (first-hand, one honeypot) |
| 2026-10-18 | The PoC repository `code-zm/plex2shell` is created on GitHub | [13] | Confirmed |
| 2026-10-19 | Plex's update: CVE details, the chain, active and wide exploitation, miners and proxy software, IOCs; CISA's SSVC entry for -96656 moves to exploitation active | [9] [4] | Confirmed |
| 2026-10-19 | SecurityWeek and The Hacker News report the attacks | [15] [17] | Reported |
| 2026-10-20 | CISA adds all four to KEV; SSVC moves to exploitation active for -96652, -96654 and -96655 | [7] [1] [2] [3] | Confirmed |
| 2026-10-21 | BleepingComputer reports CISA's warning | [16] | Reported |
| 2026-10-23 | KEV due date for -96654 and -96656 | [7] | Confirmed |
| 2026-11-03 | KEV due date for -96652 and -96655 | [7] | Confirmed |
| 2026-11-04 | This study's lab run (UTC) | [38] [39] [40] [41] | Demonstrated |

### Three dates that disagree

- **The PoC date.** Plex and SecurityWeek put the write-up and the PoC on 16 October [9] [15]. BleepingComputer says the PoC followed the write-up by three days [16]. The repository that hosts it now was created on 18 October [13]. The defensible statement is that the write-up went public on 16 October, Plex dates the public PoC to the same day, and the current repository dates from 18 October (**Inferred** from the Confirmed dates).
- **The fix date.** The Hacker News dates the fix to 3 August, the Beta [17]; BleepingComputer to 4 August, the general release [16]. The vendor's release thread supports both [10].
- **The CVE release date.** The CISA advisory gives 3 August as each CVE's release date, while the CVE records were reserved and published on 23 September [6] [5].

### Which CVE is which step

The primaries disagree, and a defender reading only one of them will mislabel at least one step (**Confirmed** disagreement) [9] [1] [2] [3] [4] [6] [7] [13]:

| CVE | NVD, CISA advisory and KEV | Plex's CVE table (19 October) | PoC README |
|---|---|---|---|
| CVE-2026-96652 | SSRF via `/player/timeline` | Unauthenticated timeline SSRF | Not recorded here |
| CVE-2026-96654 | `searchOne` URL values not neutralized | Access to internal agent functions over loopback | Not recorded here |
| CVE-2026-96655 | Authenticated SSRF via `/video/:/transcode/universal` | Disclosure of the server owner's admin token | Owner-authenticated transcoder SSRF plus file write |
| CVE-2026-96656 | Admin file write; unsigned `.so` load | Arbitrary file write to Codecs through transcoder preferences | Not recorded here |

In the researcher's own write-up, the token theft comes out of the `searchOne` pivot (stage 3) [12]. This study uses the CVE record wording for each id.

### The version trap

The advisory's title is "Important Security Update for Plex Media Server v1.43.2 and earlier", and its first post, on 1 September, asks owners to update to "1.43.3 or newer" [9]. Read alone, both suggest 1.43.3.10828 is safe. It is not: every CVE record, the CISA advisory and Plex's own update of 19 October put the fixed line at 1.43.3.10861 (**Inferred** from the Confirmed records) [5] [6] [9]. NVD adds to the confusion. Its "Release Notes" reference is the release post for 1.43.3.10828 of 14 July, the last vulnerable 1.43.3 build, not the fixed one [10]. The fixed build's notes carry two security lines that 1.43.3.10828 lacks: PM-5763, a potential CompanionProxy vulnerability, and PM-5766, which stops `TranscoderH264Options` and `TranscoderH264OptionsOverride` being changed over the network (**Confirmed**) [10].

### Scores and ratings

All CVSS scores are CISA's as CNA [1] [2] [3] [4]. CISA's advisory carries a risk note: in the worst case, a remote attacker could steal account credentials and then write files or run code [6]. CISA's SSVC entries in the NVD records moved exploitation from none to active on 20 October 2026, and on 19 October for CVE-2026-96656 [1] [2] [3] [4]. The GitHub advisories mirror the NVD severities: medium for -96652, -96654 and -96655, high for -96656 [8].

## Part 3: exploitation in the wild

- **The first sighting.** An independent honeypot operator first saw Plex2Shell exploitation on the morning of 17 October 2026, from `45.194.92.222`, with further attempts from `91.92.40.202` and `176.65.139.228` (**Confirmed** as the operator's first-hand observation) [14]. Two files, `docker` (which the operator says contained a cryptominer) and a UPX-packed binary named `x`, were downloaded from `217.60.194.116`; a later update that day added an XMRig sample and the proxy tool `myawesomeproxy` [14]. The operator reports a `Python-urllib/3.10` user agent and `sslip.io` callback hostnames, and has published packet captures from their own lab test of the chain, for signature work, at `github.com/BoredHackerBlog/plex2shell_pcap`, which was not opened for this study [14]. These indicators cover one honeypot only, and the operator notes it [14].
- **The vendor's account.** Plex says the flaws have been actively and widely exploited since the public PoC, in attacks on unpatched internet-facing servers, and that compromised servers ran cryptocurrency miners and proxy software that routes other people's traffic through the victim's connection (**Confirmed**: Plex) [9].
- **CISA.** All four CVEs entered KEV on 20 October 2026, each marked as chainable with the other three. Known ransomware use is Unknown. Only CVE-2026-96656 is flagged for forensic triage. The required action cites Binding Operational Directive 26-04 (**Confirmed**) [7].
- **The press.** SecurityWeek reports that exploitation began one day after the write-up and PoC, with an XMRig-based miner and `myawesomeproxy` dropped, and notes that Plex shipped the fixes before announcing them (**Reported**) [15]. The Hacker News reports a shell script fetching the miner `x12345` and a miner process `mylovelyminer` pointing at a `proxystream.st` host. It cites Bitsight as linking `proxystream.st` infrastructure to the AISURU DDoS and proxyware botnet, and Reddit users reporting the same miner with the cause unconfirmed (**Reported**) [17]. BleepingComputer covers CISA's warning (**Reported**) [16].
- **Who.** No source opened attributes the exploitation to a named group, KEV marks ransomware use as Unknown, and every observed payload is a cryptominer or proxyware (**Inferred** from the sources opened) [7] [9] [14].

## Part 4: what the lab showed

The lab ran on a Linux lab host with Docker on 4 November 2026 UTC, with every published port bound to `127.0.0.1`, every server left unclaimed (no Plex account sign-in), and every container removed afterwards [38] [39] [40] [41]. The four CVE runs used two pairs of images. The CVE-2026-96652 run set 1.43.2.10687 against the fixed 1.43.3.10861; the other three set 1.43.3.10828, the last vulnerable 1.43.3 build, against 1.43.3.10861. The screenshots are renderings of the captured terminal output with a neutral `lab$` prompt and the lab host anonymized.

### Setup: matched pairs on loopback

The CVE-2026-96652 run pulled `plexinc/pms-docker:1.43.2.10687-563d026ea` (digest `sha256:c37106c5...`) and `plexinc/pms-docker:1.43.3.10861-07dfddaeb` (digest `sha256:5bc1d13f...`), created a named volume for each, and ran the vulnerable server on `127.0.0.1:32400` and the fixed one on `127.0.0.1:32401` (**Demonstrated**, CVE-2026-96652/01-setup.txt). Both reported `(healthy)` in `docker ps` (**Demonstrated**, CVE-2026-96652/02-test.txt). The other runs pulled `1.43.3.10828-00f62d37d` (digest `sha256:a2b03d75...`) in place of 1.43.2.10687 [39] [40] [41]. All three digests match the Docker Hub tag records [11].

![Terminal output on the lab host for the CVE-2026-96652 run: docker pull of plexinc/pms-docker 1.43.2.10687-563d026ea ending with digest sha256:c37106c5 and of 1.43.3.10861-07dfddaeb ending with digest sha256:5bc1d13f, docker volume create for plexlab-vuln-config and plexlab-fixed-config, docker run of plexlab-vuln published on 127.0.0.1:32400 and plexlab-fixed on 127.0.0.1:32401, and a wait loop printing port 32400 up and port 32401 up](/case-studies/assets/plex-media-server-2026/CVE-2026-96652/01-setup.png)

The CVE-2026-96654 and CVE-2026-96655 runs ran at the same time and first collided on the container names `plex-vuln` and `plex-fixed`. Each removed only its own container, by id, and re-ran setup from scratch (**Demonstrated**, CVE-2026-96654/01-setup-attempt1.txt and CVE-2026-96655/01-setup-attempt1-collision.txt).

### The version check

An unauthenticated `GET /identity` on each unclaimed server returned a MediaContainer carrying the build number (**Demonstrated**, CVE-2026-96652/02-test.txt):

```text
lab$ curl -s http://127.0.0.1:32400/identity
<MediaContainer size="0" apiVersion="1.2.2" claimed="0" ... version="1.43.2.10687-563d026ea">
lab$ curl -s http://127.0.0.1:32401/identity
<MediaContainer size="0" apiVersion="1.2.2" claimed="0" ... version="1.43.3.10861-07dfddaeb">
```

The `machineIdentifier` and `startState` attributes and the XML declaration line are cut from the quote. The package inside each container agreed (**Demonstrated**, CVE-2026-96652/02-test.txt):

```text
plexmediaserver	1.43.2.10687-563d026ea
plexmediaserver	1.43.3.10861-07dfddaeb
```

The other three runs showed the same agreement for 1.43.3.10828-00f62d37d against 1.43.3.10861-07dfddaeb, through `/identity` and `dpkg-query` (**Demonstrated**, CVE-2026-96654/02-test.txt, CVE-2026-96655/02-test.txt, CVE-2026-96656/02-test.txt). A gate that compares the package version gave the right answer on the first try (**Demonstrated**, CVE-2026-96656/02-test.txt; the same result is in CVE-2026-96655/02-test.txt):

```text
plex-vuln 1.43.3.10828 VULNERABLE (< 1.43.3.10861)
plex-fixed 1.43.3.10861 FIXED
```

The server log carries the version too. `docker logs` showed only `Starting Plex Media Server.`, but the server's own `Plex Media Server.log` opens with a banner such as `Plex Media Server v1.43.3.10828-00f62d37d - Docker Docker Container x86_64`, and the same line for v1.43.3.10861-07dfddaeb (**Demonstrated**: the docker logs line in CVE-2026-96656/02-test.txt; the banner in CVE-2026-96655/02-test.txt).

### The test step, described

No exploit step ran in any of the four runs: no request went to `/player/timeline`, `/system/agents/*`, `/:/prefs` or `/video/:/transcode/universal`, and the test arrays in every `plan.json` hold only version, file and preference checks (**Demonstrated**) [38] [39] [40] [41]. The lab evidence is version exposure plus a file and preference baseline, not a reproduction of the chain.

### What differed

| Observable | Vulnerable build | Fixed build 1.43.3.10861 | Capture |
|---|---|---|---|
| `/identity` MediaContainer `version` (no token, unclaimed) | `1.43.2.10687-563d026ea` or `1.43.3.10828-00f62d37d` | `1.43.3.10861-07dfddaeb` | CVE-2026-96652/02-test.txt, CVE-2026-96654/02-test.txt |
| `dpkg-query -W plexmediaserver` in the container | same as above | `1.43.3.10861-07dfddaeb` | CVE-2026-96652/02-test.txt, CVE-2026-96656/02-test.txt |
| `Plex Media Server.log` banner | `v1.43.3.10828-00f62d37d` | `v1.43.3.10861-07dfddaeb` | CVE-2026-96655/02-test.txt |
| Package-based gate | `VULNERABLE (< 1.43.3.10861)` | `FIXED` | CVE-2026-96656/02-test.txt |
| `.so` or `.dll` files in Codecs on a fresh server | `0` | no `.so` files (the listing searched `.so` only) | CVE-2026-96654/02-test.txt, CVE-2026-96655/04-mitigation.txt |
| `TranscoderH264Options` in `Preferences.xml` | `no-TranscoderH264Options`, `TranscoderH264Options not set` | `TranscoderH264Options not set` | CVE-2026-96654/02-test.txt, CVE-2026-96656/02-test.txt, CVE-2026-96656/04-mitigation.txt |

(**Demonstrated** throughout.) Only the version differs. The empty Codecs folder and the unset transcoder option are the same on both builds, which makes them a clean baseline for file-integrity monitoring: on a fresh server, anything that appears in either place later is a change to explain [39] [41].

### What the server log records about each request

`Plex Media Server.log` records every request with its source address and a locality class (**Demonstrated**, CVE-2026-96652/02-test.txt):

```text
DEBUG - Request: [172.17.0.1:40438 (Subnet)] GET /identity (6 live) #60
DEBUG - Request: [[::1]:49048 (Loopback)] GET /identity (7 live) #62
```

The first is the `curl` from the lab host, arriving through the Docker bridge; the second came from inside the container. The pms-docker README confirms that with bridge networking, traffic from the host appears to Plex as coming from the Docker gateway [22]. This matters for detection in Part 6: the chain's second stage depends on requests the server sees as loopback, and the log labels loopback requests, so those requests should be visible (**Inferred**; no chain traffic was sent in the lab).

### What contradicted the plan

**The version parser read the XML declaration.** The CVE-2026-96652 plan's verdict loop extracted every `version="..."` attribute from `/identity`. The response also carries the XML declaration, `version="1.0"`, so the loop labelled the fixed 1.43.3.10861 build as below the threshold. The run logged a DEVIATION and re-ran the loop keeping only the last match, which is the MediaContainer attribute (**Demonstrated**, CVE-2026-96652/02-test.txt):

```text
127.0.0.1:32400 1.43.2.10687-563d026ea VULNERABLE (below 1.43.3.10861)
127.0.0.1:32401 1.43.3.10861-07dfddaeb FIXED
```

The same defect made the first mitigation check report the fixed build as not patched, before the corrected run printed `fixed container reports 1.43.3.10861-07dfddaeb: at or above 1.43.3.10861 (patched)` (**Demonstrated**, CVE-2026-96652/04-mitigation.txt). The CVE-2026-96654 run used a loop with the same defect and was not re-run, so its verdict line is wrong for the fixed build and is not used in this study; the `dpkg-query` cross-check is the reliable observable in that capture (**Demonstrated**, CVE-2026-96654/02-test.txt).

**The version was not in the container log.** The CVE-2026-96656 plan expected the server version in `docker logs`. It showed only `Starting Plex Media Server.`; the banner is in `Plex Media Server.log` (**Demonstrated**: CVE-2026-96656/02-test.txt for the docker logs line; CVE-2026-96655/02-test.txt for the banner).

### The exposure check on the lab host

The exposure checks ran on the lab host itself (**Demonstrated**, CVE-2026-96652/03-exposure.txt). `ss -ltn` showed only `127.0.0.1:32400` and `127.0.0.1:32401` listening. The host's `dpkg-query -W plexmediaserver` reported `no packages found matching plexmediaserver`, and `rpm -q plexmediaserver` reported `package plexmediaserver is not installed`, while `docker ps` listed both Plex images. A host package check alone misses a containerized server (the outputs **Demonstrated**; the conclusion **Inferred**).

![Terminal output on the lab host for the CVE-2026-96652 exposure check: curl of /identity on 127.0.0.1:32400 piped to grep for version attributes prints version="1.0" and version="1.43.2.10687-563d026ea", the same on port 32401 prints version="1.0" and version="1.43.3.10861-07dfddaeb", ss -ltn shows listeners on 127.0.0.1:32400 and 127.0.0.1:32401 only, dpkg-query reports no packages found matching plexmediaserver, rpm -q reports package plexmediaserver is not installed, and docker ps lists plexlab-fixed on 1.43.3.10861-07dfddaeb and plexlab-vuln on 1.43.2.10687-563d026ea](/case-studies/assets/plex-media-server-2026/CVE-2026-96652/03-exposure.png)

The CVE-2026-96654 run added the vendor's indicator hunt to the exposure check: a `find` for `.so` or `.dll` files under any `Plex Media Server/Codecs` path newer than `/etc/hostname`, and a process search for `myawesomeproxy`, `mylovelyminer` or `x12345`. Both returned nothing on the lab host (**Demonstrated**, CVE-2026-96654/03-exposure.txt).

![Terminal output on the lab host for the CVE-2026-96654 exposure check and IOC hunt: a dpkg-query or rpm check reports package plexmediaserver is not installed, curl of /identity on port 32400 prints version="1.0" and version="1.43.3.10828-00f62d37d", docker ps lists plex-fixed on 1.43.3.10861-07dfddaeb and plex-vuln on 1.43.3.10828-00f62d37d, ss shows 127.0.0.1:32400 listening, and the find for .so and .dll files under Plex Media Server Codecs paths and the ps search for myawesomeproxy, mylovelyminer and x12345 both print nothing](/case-studies/assets/plex-media-server-2026/CVE-2026-96654/03-exposure.png)

The CVE-2026-96655 run tried the native-install paths as well. On a Docker-only host, the log under `/var/lib/plexmediaserver` and the Codecs folder there do not exist, so those checks fail with `No such file or directory`; the Windows registry check was not run on the Linux host (**Demonstrated**, CVE-2026-96655/03-exposure.txt).

![Terminal output on the lab host for the CVE-2026-96655 exposure check: docker ps lists plex-fixed on 1.43.3.10861-07dfddaeb and plex-vuln on 1.43.3.10828-00f62d37d, dpkg-query and rpm report no plexmediaserver package on the host, curl of /identity on port 32400 returns a MediaContainer with claimed="0", grep for the version banner in the native Linux log path and find in the native Codecs path both report No such file or directory, a comment notes the Windows registry check was not run, and ss shows 127.0.0.1:32400 listening](/case-studies/assets/plex-media-server-2026/CVE-2026-96655/03-exposure.png)

### The fix, verified

Mitigation was verified read-only (**Demonstrated**, CVE-2026-96652/04-mitigation.txt, CVE-2026-96655/04-mitigation.txt, CVE-2026-96656/04-mitigation.txt). The fixed container reported 1.43.3.10861-07dfddaeb, at or above the threshold, its package agreed, and `docker port` and `docker inspect` showed the published ports bound to loopback only. The fixed server's preferences carried no `TranscoderH264Options` value. The vendor workaround, turning Remote Access off, was not tested, because the servers were unclaimed and Remote Access needs a server signed in to a Plex account [23].

![Terminal output on the lab host for the CVE-2026-96652 mitigation check: docker inspect shows plexlab-fixed on plexinc/pms-docker 1.43.3.10861-07dfddaeb; a first version check that reads every version attribute prints fixed container reports 1.0 and then 1.43.3.10861-07dfddaeb: NOT patched; docker inspect of the port bindings shows 32400/tcp published on 127.0.0.1:32400 and 127.0.0.1:32401 only; a DEVIATION line notes the corrected parse; and the corrected check prints fixed container reports 1.43.3.10861-07dfddaeb: at or above 1.43.3.10861 (patched)](/case-studies/assets/plex-media-server-2026/CVE-2026-96652/04-mitigation.png)

The screenshot keeps the defective first check, because it is the clearest picture of the parsing trap: the first verdict is wrong, and the corrected one below it is right.

![Terminal output on the lab host for the CVE-2026-96656 mitigation verification: curl of /identity on 127.0.0.1:32401 prints version="1.0" and version="1.43.3.10861-07dfddaeb", docker port shows plex-vuln on 127.0.0.1:32400 and plex-fixed on 127.0.0.1:32401, and a grep for TranscoderH264Options in the fixed server's Preferences.xml prints TranscoderH264Options not set](/case-studies/assets/plex-media-server-2026/CVE-2026-96656/04-mitigation.png)

### Cleanup, verified

Cleanup was verified for the CVE-2026-96652, -96654 and -96656 runs: containers, volumes and images removed, the lab ports clear, `docker ps -a` empty, and each work directory gone (**Demonstrated**, 05-cleanup.txt in each directory).

![Terminal output on the lab host for the CVE-2026-96652 cleanup: docker rm -f removes plexlab-vuln and plexlab-fixed, docker volume rm removes both config volumes, docker rmi untags and deletes both pms-docker images, the ss check prints clean, docker ps -a prints only its header row, the volume and image checks print no plexlab volumes and no pms-docker images, and the work directory check prints removed](/case-studies/assets/plex-media-server-2026/CVE-2026-96652/05-cleanup.png)

The CVE-2026-96655 run was not fully clean. Its containers, images and listeners were removed, but removing the bind-mounted config folders under `/tmp/lab` failed with `Permission denied`, leaving two empty directory skeletons owned by root that the unprivileged lab user could not remove; `/tmp` on the lab host is a tmpfs that clears on reboot (**Demonstrated**, CVE-2026-96655/05-cleanup.txt and plan.json). The other runs mounted no host folder: the CVE-2026-96652 run used named volumes and removed them with `docker volume rm`, and the -96654 and -96656 runs removed their containers with `docker rm -f -v` (**Demonstrated**, 05-cleanup.txt in each directory). For anyone repeating the lab, avoiding a bind mount avoids the leftover (**Inferred**).

![Terminal output on the lab host for the CVE-2026-96655 cleanup: docker rm -f removes plex-vuln and plex-fixed, docker rmi untags and deletes the 1.43.3.10828 and 1.43.3.10861 images, rm -rf of the bind-mount folder under /tmp/lab reports Permission denied for the two Plex Media Server config directories, the port check prints ports clear, docker ps -a and docker images report nothing left, docker network ls lists bridge, host and none, a second rm -rf hits the same Permission denied, and a find listing shows the empty Library and Application Support directories owned by root under each config folder](/case-studies/assets/plex-media-server-2026/CVE-2026-96655/05-cleanup.png)

### What the lab does and does not show

It shows, on one host on one date, that the official images report their build number through three separate observables (the `/identity` response, the package database and the server log), that a version gate built on the package or on the MediaContainer attribute tells 1.43.3.10828 from 1.43.3.10861, that a host package check misses a containerized server, and that a fresh server has an empty Codecs folder and no transcoder override (**Demonstrated**) [38] [39] [40] [41]. It does not show the chain: no exploit step ran, and the chain mechanics rest on the researcher and the vendor [12] [9]. It does not show whether a claimed server answers `/identity` without a token, which was not checked, and it does not test the Remote Access workaround (**Inferred** limits).

## Part 5: find it and fix it on real hosts

### Read the version, by platform

| Platform | Where the data lives | Read the version | Fix | Source |
|---|---|---|---|---|
| Any | Plex Web | Settings, General | Update to 1.43.3.10861 or later | [9] |
| Any, over the network | TCP 32400 | `curl -s http://HOST:32400/identity`, then read the MediaContainer `version` attribute, never the XML declaration; tested only on unclaimed servers | as above | [38] (**Demonstrated**); claimed servers not checked |
| Debian, Ubuntu | `/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/` | `dpkg-query -W plexmediaserver` | From the Plex repository, `sudo apt install -y plexmediaserver`; or `sudo dpkg -i` on the downloaded `.deb` | [18] [21] [9]; check [38] |
| Fedora, CentOS | same data path | `rpm -q plexmediaserver` | `sudo dnf install -y plexmediaserver` from the repository (rpm 4.16 or later), or `sudo dnf install` on the downloaded `.rpm` | [18] [21] [9] |
| Linux repository users | `/etc/apt/sources.list.d/plex*`, `/etc/yum.repos.d/plex*` | | The repositories changed starting with 1.43.0: remove the old repository files and add `repo.plex.tv`, signed with `PlexSign.v2.key`. A host still pointing at the old repository would not receive the fixed build (**Inferred**) | [21] |
| Snap | `/var/snap/plexmediaserver/common/Library/Application Support` | Plex Web | Not documented in the sources opened | [18] |
| Synology DSM 7 | `/volume1/PlexMediaServer/AppData/Plex Media Server` | Plex Web | Manual package install on the NAS | [18] [9] |
| Docker | `/config/Library/Application Support/Plex Media Server` inside the container | Image tag from `docker ps`; `docker exec <container> dpkg-query -W plexmediaserver`; the banner in `Plex Media Server.log` | Move to a pinned tag at 1.43.3.10861 or later, per the pms-docker README. The `public` and `beta` tags install the latest server at start and update on restart | [22] [9]; checks [38] [40] |
| Windows | `%LOCALAPPDATA%\Plex Media Server`; preferences in the registry at `HKEY_CURRENT_USER\Software\Plex, Inc.\Plex Media Server` | Plex Web | Automatic updates or the Downloads page | [18] [19] [9] |
| macOS | `~/Library/Application Support/Plex Media Server/`; preferences in `~/Library/Preferences/com.plexapp.plexmediaserver.plist` | Plex Web | Automatic updates or the Downloads page | [18] [19] [9] |
| NVIDIA Shield | | Plex Web | Google Play updates | [9] |

The Codecs folder and, on Linux, `Preferences.xml` live in the data directory [18]. On Windows and macOS, server preferences live in the registry key or the plist, so the `TranscoderH264Options` check belongs there, not in a file (**Inferred** from [19]). Logs are in `%LOCALAPPDATA%\Plex Media Server\Logs` on Windows, `~/Library/Logs/Plex Media Server/` on macOS, and a `Logs` folder in the data directory on Linux and NAS, usually owned by `plex:plex`; they can also be downloaded from the server's troubleshooting settings [20].

### If the server was exposed

Plex's guidance for any server older than 1.43.3.10861 that was reachable from the internet is to assume it may be compromised (**Confirmed**: Plex) [9]:

1. Rebuild from a clean install rather than reusing the old data directory.
2. At minimum, delete the contents of the Codecs folder and check the server preferences for transcoder options you did not set.
3. Sign out of all devices and change the Plex password.
4. Treat anything the server's service account could reach as exposed.

KEV's forensic-triage flag on CVE-2026-96656 points the same way: on an exposed server, patching closes the door but does not clear what came through it [7].

### If you cannot update today

Turn Remote Access off if you do not need it (Settings, Remote Access in the vendor's advisory; Settings, Server, Remote Access in the support article), and do not forward port 32400 directly [9] [23]. Remote Access maps an external port to the internal 32400 through UPnP, NAT-PMP or a manual forward, so check the router as well as the server [23]. The pms-docker README warns that `ALLOWED_NETWORKS` allows access without authorization, so keep it narrow [22]. None of this was tested in the lab.

## Part 6: detection

| What to look for | Where | Basis | Grade |
|---|---|---|---|
| Any server, image or package below 1.43.3.10861 | `/identity`, image tags, package databases | Version line [5]; method [38] | Confirmed; Demonstrated |
| Plex images on hosts with no Plex package | `docker ps`, `docker images` on every container host | [38] | Demonstrated |
| `/system/agents/*` requests labelled `(Loopback)` shortly after a `/player/timeline` request from a WAN or Subnet client | `Plex Media Server.log` | Locality labels [38]; chain [12] | Inferred |
| `/player/timeline` requests whose `protocol=` value is a full URL | `Plex Media Server.log`, reverse proxy logs | [1] [12] | Inferred |
| `/video/:/transcode/universal` requests whose `path=` points at an external or loopback URL | as above | [3] [12] | Inferred |
| Writes to `/:/prefs` touching `TranscoderH264Options` | as above | [4] [10] [12] | Inferred |
| A `TranscoderH264Options` value you did not set | `Preferences.xml`, registry or plist | [9] [19]; clean baseline [41] | Confirmed; Demonstrated |
| New `.so` or `.dll` files in Codecs | File-integrity monitoring on the data directory | [9]; clean baseline [39] | Confirmed; Demonstrated |
| Processes started by Plex named `myawesomeproxy`, `mylovelyminer` or `x12345`, or an XMRig miner | Process telemetry, children of the `plex` user | [9] [14] | Confirmed |
| Outbound connections to `proxystream.st`; outbound requests from the Plex process to names that begin with `127.0.0.1` but resolve elsewhere, such as `sslip.io` names | DNS and egress logs | [9] [12] [14] | Confirmed (vendor IOC); Inferred (rule) |
| Sustained high CPU while nothing plays | Host monitoring | [9] | Confirmed |
| The honeypot's source addresses and `Python-urllib/3.10` user agent | Firewall and web logs | One honeypot only [14] | Weak signal |

With Docker bridge networking, requests from the host side appear in the log as coming from the Docker gateway address, `172.17.0.1` in the lab, labelled `(Subnet)` [38] [22]. Shipping the log to a SIEM is easier with syslog output, which Plex enables with `PLEX_MEDIA_SERVER_USE_SYSLOG=true` (on systemd, in an `override.conf` for the service) [19]. The request-pattern rules in the table are this study's reading of the record, not tested signatures (**Inferred**); the packet captures the honeypot operator recorded in their own lab test of the public chain are a starting point for testing them [14].

## Part 7: the vulnerability-management view

- **Score each CVE, but triage the chain.** A program that sorts by individual CVSS would see three Mediums and one High that needs admin rights, and might schedule them for the next routine cycle. The chain is unauthenticated remote code execution, and it was exploited within about a day of the write-up [12] [14]. KEV's note that each entry chains with the other three is the signal to treat them as one item [7].
- **The fix date and the disclosure date are different clocks.** The fixed build shipped on 4 August, and exploitation started on 17 October [10] [14]. Owners who reached 1.43.3.10861 before 16 October were patched before the public write-up and PoC; owners who read "1.43.3 or newer" and stopped at 1.43.3.10828 were not (**Inferred**) [9] [10].
- **Consumer software on business networks.** Plex Media Server is home media software, and it runs on NAS devices, desktops and containers that a corporate asset inventory may never list. KEV's due dates are set under a CISA directive, but the inventory gap applies to anyone whose staff run home servers on networks they also use for work, or who host Plex on shared infrastructure (**Inferred**).
- **Version checks are only as good as the parser.** The lab's own parse defect is a small version of a common scanner failure: read the wrong attribute and a fixed host is flagged, or a vulnerable one is cleared [38] [39]. A gate built on the package database, or on the single attribute that carries the build number, avoids it.

### Overstated and understated

- **Overstated:** the honeypot's source addresses and user agent as a detection basis, because they come from one honeypot and the operator says so (**Confirmed** as one operator's observation [14]); and the link between `proxystream.st` and the AISURU botnet, which rests on one press report citing a vendor (**Reported** [17]). No opened source names a group, and KEV lists ransomware use as Unknown (**Confirmed** [7]).
- **Understated:** the severity of the chain, which no CVSS record scores while each CVE alone scores Medium or High (**Confirmed** [1] [2] [3] [4]; the chain rating is the researcher's [12]); the affected range, which the advisory title puts at "v1.43.2 and earlier" although 1.43.3.10828 is vulnerable (**Inferred** from [5] [6] [9]); and exposure on hosts where Plex runs only in containers, which a package-based inventory misses (**Demonstrated** [38]).

## Part 8: MITRE mappings

Each technique below is this study's binding of the record's attack path to the technique's definition, with the basis stated; every id was checked on the live ATT&CK page (v20.0) and against the library's generated pages [24] to [30] [37].

### ATT&CK Enterprise techniques

Tactic names follow ATT&CK v20.0, where the former Defense Evasion tactic is split into Stealth and Defense Impairment.

| ATT&CK id | Name | Tactic (v20) | Dated event or report | Basis | Source |
|---|---|---|---|---|---|
| [T1190](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | Plex's update (2026-10-19); honeypot exploitation (2026-10-17) | Plex: the chained issues let an unauthenticated remote attacker run code (Confirmed) | [9] [14] [24] |
| [T1528](/mitre/techniques/T1528.md) | Steal Application Access Token | Credential Access | Plex's CVE table for -96655 (2026-10-19); researcher stage 3 (2026-10-16) | Theft of the server owner's token (Confirmed) | [9] [12] [25] |
| [T1129](/mitre/techniques/T1129.md) | Shared Modules | Execution | NVD record for -96656 (2026-09-23); researcher stage 5 (2026-10-16) | Every `.so` in Codecs is loaded and run at startup (Confirmed) | [4] [12] [26] |
| [T1105](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | Researcher stage 4 (2026-10-16); honeypot payload download (2026-10-17) | The transcoder fetches an attacker-hosted file; miner and binary downloaded in the wild (Confirmed) | [12] [14] [27] |
| [T1496.001](/mitre/techniques/T1496-001.md) | Resource Hijacking: Compute Hijacking | Impact | Plex's update (2026-10-19); honeypot XMRig (2026-10-17) | Cryptocurrency miners on compromised servers (Confirmed) | [9] [14] [28] |
| [T1496.002](/mitre/techniques/T1496-002.md) | Resource Hijacking: Bandwidth Hijacking | Impact | Plex's update (2026-10-19); honeypot `myawesomeproxy` (2026-10-17) | Proxy software routing other people's traffic through the victim (Confirmed) | [9] [14] [28] |
| [T1059.004](/mitre/techniques/T1059-004.md) | Command and Scripting Interpreter: Unix Shell | Execution | Researcher write-up (2026-10-16); The Hacker News report (2026-10-19) | The public PoC opens a reverse shell [12]; The Hacker News reports a shell script fetching the miner x12345 in the wild (Reported) [17] | [12] [17] [30] |

Two techniques used by earlier lab plans are left out. T1574 Hijack Execution Flow (tactics Stealth and Execution on the live page) fits the `.so` load less well than T1129, because nothing is hijacked: the server loads every library in the folder by design [26]. T1090.001 Proxy: Internal Proxy is a weak fit for the loopback SSRF pivot, which is a forged request, not a relay (**Inferred**). T1595.002 Active Scanning: Vulnerability Scanning is also left out: the honeypot operator reports mostly generic scanning and exploitation attempts, not scanning for these CVEs [14] [29] (**Inferred**). ATT&CK for ICS and ATT&CK for Mobile do not apply.

### Group, software and campaign objects

None is bound. No source opened attributes the exploitation to a named actor, and a search of the library for Plex returned no relevant group, software or campaign page [37]. The ATT&CK site search was not checked.

### CWE and CAPEC

| Id | Name | Where it appears | Source |
|---|---|---|---|
| CWE-918 | Server-Side Request Forgery (SSRF) | CVE-2026-96652 and CVE-2026-96655 in NVD, KEV and the CISA advisory | [1] [3] [6] [7] [31] |
| CWE-84 | Improper Neutralization of Encoded URI Schemes in a Web Page | CVE-2026-96654, same sources | [2] [6] [7] [32] |
| CWE-73 | External Control of File Name or Path | CVE-2026-96656, same sources | [4] [6] [7] [33] |
| [CAPEC-664](/mitre/capec/CAPEC-664.md) | Server Side Request Forgery | The CAPEC that the CWE-918 page lists; the library page links CWE-918 | [31] [34] [37] |
| [CAPEC-76](/mitre/capec/CAPEC-76.md) | Manipulating Web Input to File System Calls | Linked to CWE-73 on the library page; its binding to CVE-2026-96656 is Inferred | [35] [37] |

The CWE-84 page lists no related CAPEC, so none is bound for CVE-2026-96654 [32]. The library has no per-id CWE pages; see the [CWE Reference](/CWE_REFERENCE.md).

### D3FEND countermeasures

Each id was confirmed through the D3FEND API, and each has a page in the library [36] [37]:

| Countermeasure | Id | Why it applies here | Library tactic or mapped technique |
|---|---|---|---|
| [Software Update](/mitre/d3fend/software-update.md) | D3-SU | The vendor fix: 1.43.3.10861 or later | Harden |
| [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) | D3-AVE | Finding every server, image and package below the fixed line, containers included | Model |
| [Disable Remote Access](/mitre/d3fend/disable-remote-access.md) | D3-DRA | The vendor workaround: Remote Access off | Harden |
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) | D3-ITF | No direct forward of 32400 | Mapped to T1190 |
| [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) | D3-OTF | Blocking the transcoder's fetches and the miners' and proxies' callbacks | Mapped to T1105 |
| [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) | D3-FIM | Codecs and the server preferences, against the clean baseline | Detect |
| [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) | D3-PSA | Unknown processes started by Plex | Detect |
| [Credential Rotation](/mitre/d3fend/credential-rotation.md) | D3-CRO | Change the Plex password | Mapped to T1528 |
| [Credential Revocation](/mitre/d3fend/credential-revocation.md) | D3-CR | Sign out of all devices | Mapped to T1528 |
| [URL Analysis](/mitre/d3fend/url-analysis.md) | D3-UA | URL values in `protocol=` and `path=` parameters | Inferred fit |
| [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) | D3-ACH | Clearing transcoder options you did not set | Inferred fit |

The last column gives the library page's D3FEND tactic, or the ATT&CK technique the library maps the countermeasure to; the "why it applies" column is this study's reading (**Inferred**). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### Navigator layer

[navigator/library-layers/plex-media-server-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/plex-media-server-2026.json) carries the seven technique entries above (ATT&CK v20, domain `enterprise-attack`), listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md). Score 100 marks bindings a primary source supports for these CVEs (T1190, T1528, T1129, T1105, T1496.001, T1496.002); score 60 marks bindings that rest on a single press report (T1059.004). Scores mean evidence basis, not frequency or severity. Each entry's comment names the source numbers in this study.

MITRE ATT&CK, CWE, CAPEC and D3FEND content is used under the terms recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

## Cross-cutting themes

- **Chains beat scores.** Four individually moderate CVEs became an unauthenticated remote code execution, the same lesson that runs through [PHP2Shell and the October 2026 Attack Wave](/case-studies/PHP2SHELL_OCTOBER_2026.md), which records the Plex KEV additions in the same week, and through [Log4Shell](/case-studies/LOG4SHELL.md), where a logging feature became a remote fetch (**Inferred**) [7] [12].
- **Loopback is not a trust boundary.** The chain's pivot is a server that trusts its own loopback origin and a framework that attaches a secret to any URL that starts with `http://127.0.0.1` [12]. Any service that treats "came from localhost" as "came from me" can be walked into the same shape by a request-forgery bug (**Inferred**).
- **A plugin folder is a code path.** The final stage works because the transcoder loads every library in a writable folder with no signature check [4] [12]. A folder an application loads code from deserves the monitoring and permissions of the application binary itself (**Inferred**).
- **Advisory wording is part of the fix.** A title that says "v1.43.2 and earlier" and a first post that says "1.43.3 or newer" left room to stop at the last vulnerable build, and NVD's release-notes link pointed at it [9] [10]. Defenders should read the version boundary from the CVE record, not the headline (**Inferred**).
- **Machine-assisted research is in the record.** The researcher describes a workflow that used language models heavily for recon, hunting, verification and chaining, with the judgement calls kept human [12]. The direction matches [the AI Threats 2026 study](/case-studies/AI_THREATS_2026.md) and [the CVE-2026-98432 study](/case-studies/LINUX_TCP_UAF_2026.md) (**Inferred**).
- **Lab plans are hypotheses.** The plans expected a version in `docker logs` and a working version parser; the runs found neither, and writing the expectation down first is how both corrections reached this study [38] [41].

## Sources

Sources 1 to 37 were opened on 4 November 2026; sources 38 to 41 are the lab capture sets, recorded on 4 November 2026 UTC.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | NVD record CVE-2026-96652 (API 2.0; published 2026-09-23; CISA ADP SSVC) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-96652 | 2026-11-04 | Confirmed |
| 2 | NVD record CVE-2026-96654 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-96654 | 2026-11-04 | Confirmed |
| 3 | NVD record CVE-2026-96655 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-96655 | 2026-11-04 | Confirmed |
| 4 | NVD record CVE-2026-96656 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-96656 | 2026-11-04 | Confirmed |
| 5 | CVE records CVE-2026-96652, -96654, -96655 and -96656 (CNA CISA, assigner `cisa-cg`), each at the same API path | https://cveawg.mitre.org/api/cve/CVE-2026-96652 | 2026-11-04 | Confirmed |
| 6 | CISA CSAF advisory VA-26-266-01 (initial release 2026-09-23) | https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-266-01.json | 2026-11-04 | Confirmed |
| 7 | CISA Known Exploited Vulnerabilities feed (catalog 2026.11.03) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-04 | Confirmed |
| 8 | GitHub advisories GHSA-5p7w-r379-3c2m, GHSA-3j7c-jr86-m5jq, GHSA-9x88-w2p7-56vh and GHSA-2g2v-9wf5-6m3g | https://github.com/advisories/GHSA-2g2v-9wf5-6m3g | 2026-11-04 | Confirmed |
| 9 | Plex, "Important Security Update for Plex Media Server v1.43.2 and earlier" (post 1 of 2026-09-01; update of 2026-10-19, edited 2026-10-20) | https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319 | 2026-11-04 | Confirmed |
| 10 | Plex Media Server release-notes thread (post 711 for 1.43.3.10828 of 2026-07-14; the 1.43.3.10861 Beta and general release posts of 2026-08-03 and 2026-08-04) | https://forums.plex.tv/t/plex-media-server/30447/711 | 2026-11-04 | Confirmed |
| 11 | Docker Hub tag records for `plexinc/pms-docker` 1.43.2.10687-563d026ea, 1.43.3.10828-00f62d37d and 1.43.3.10861-07dfddaeb | https://hub.docker.com/v2/repositories/plexinc/pms-docker/tags/1.43.3.10861-07dfddaeb | 2026-11-04 | Confirmed |
| 12 | Zach Main, "Plex2Shell" (2026-10-16) | https://zmain.info/blog/plex2shell | 2026-11-04 | Confirmed (researcher primary) |
| 13 | PoC repository `code-zm/plex2shell` (GPL-3.0, created 2026-10-18); metadata and README CVE table only, recorded by name and not linked | `github.com/code-zm/plex2shell` | 2026-11-04 | Confirmed (metadata) |
| 14 | boredhackerblog, "Plex vulnerabilities being exploited in the wild to drop a cryptominer" (independent honeypot write-up, 2026-10-17, edited 2026-10-17 and 2026-10-18) | https://www.boredhackerblog.info/2026/10/plex-vulnerabilities-being-exploited-in.html | 2026-11-04 | Confirmed (first-hand, one honeypot) |
| 15 | SecurityWeek, Plex2Shell exploitation report (2026-10-19) | https://www.securityweek.com/plex2shell-exploit-chain-weaponized-against-plex-servers-hours-after-disclosure/ | 2026-11-04 | Reported |
| 16 | BleepingComputer, CISA warning on Plex2Shell (2026-10-21) | https://www.bleepingcomputer.com/news/security/cisa-hackers-chain-plex-flaws-in-plex2shell-attacks-to-breach-servers/ | 2026-11-04 | Reported |
| 17 | The Hacker News, Plex2Shell exploitation report (2026-10-19) | https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html | 2026-11-04 | Reported |
| 18 | Plex support, "Where is the Plex Media Server data directory located?" | https://support.plex.tv/articles/202915258-where-is-the-plex-media-server-data-directory-located/ | 2026-11-04 | Confirmed |
| 19 | Plex support, "Advanced, Hidden Server Settings" | https://support.plex.tv/articles/201105343-advanced-hidden-server-settings/ | 2026-11-04 | Confirmed |
| 20 | Plex support, "Plex Media Server Logs" (served at this URL) | https://support.plex.tv/articles/200250417-plex-media-server/ | 2026-11-04 | Confirmed |
| 21 | Plex support, "Enable repository updating for supported Linux server distributions" | https://support.plex.tv/articles/235974187-enable-repository-updating-for-supported-linux-server-distributions/ | 2026-11-04 | Confirmed |
| 22 | `plexinc/pms-docker` README | https://github.com/plexinc/pms-docker/blob/master/README.md | 2026-11-04 | Confirmed |
| 23 | Plex support, "Remote Streaming (Setting Up Remote Access)" | https://support.plex.tv/articles/200289506-remote-access/ | 2026-11-04 | Confirmed |
| 24 | MITRE ATT&CK T1190 | https://attack.mitre.org/techniques/T1190/ | 2026-11-04 | Confirmed |
| 25 | MITRE ATT&CK T1528 | https://attack.mitre.org/techniques/T1528/ | 2026-11-04 | Confirmed |
| 26 | MITRE ATT&CK T1129 | https://attack.mitre.org/techniques/T1129/ | 2026-11-04 | Confirmed |
| 27 | MITRE ATT&CK T1105 | https://attack.mitre.org/techniques/T1105/ | 2026-11-04 | Confirmed |
| 28 | MITRE ATT&CK T1496.001 and T1496.002 | https://attack.mitre.org/techniques/T1496/002/ | 2026-11-04 | Confirmed |
| 29 | MITRE ATT&CK T1595.002 | https://attack.mitre.org/techniques/T1595/002/ | 2026-11-04 | Confirmed |
| 30 | MITRE ATT&CK T1059.004 | https://attack.mitre.org/techniques/T1059/004/ | 2026-11-04 | Confirmed |
| 31 | CWE-918 Server-Side Request Forgery (SSRF) (CWE 5.0) | https://cwe.mitre.org/data/definitions/918.html | 2026-11-04 | Confirmed |
| 32 | CWE-84 Improper Neutralization of Encoded URI Schemes in a Web Page | https://cwe.mitre.org/data/definitions/84.html | 2026-11-04 | Confirmed |
| 33 | CWE-73 External Control of File Name or Path | https://cwe.mitre.org/data/definitions/73.html | 2026-11-04 | Confirmed |
| 34 | CAPEC-664 Server Side Request Forgery | https://capec.mitre.org/data/definitions/664.html | 2026-11-04 | Confirmed |
| 35 | CAPEC-76 Manipulating Web Input to File System Calls | https://capec.mitre.org/data/definitions/76.html | 2026-11-04 | Confirmed |
| 36 | MITRE D3FEND API, Software Update and the other countermeasures in the D3FEND table | https://d3fend.mitre.org/api/technique/d3f:SoftwareUpdate.json | 2026-11-04 | Confirmed |
| 37 | Library data on main: the `mitre/` tree (techniques, CAPEC and D3FEND pages) and a code search for Plex | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-04 | Confirmed |
| 38 | Lab captures for CVE-2026-96652: `plan.json`, `01-setup.txt`, `02-test.txt`, `03-exposure.txt`, `04-mitigation.txt`, `05-cleanup.txt`, and the embedded screenshots `01-setup.png`, `03-exposure.png`, `04-mitigation.png` and `05-cleanup.png` | not published | 2026-11-04 | Demonstrated |
| 39 | Lab captures for CVE-2026-96654: `plan.json`, `01-setup-attempt1.txt`, `01-setup.txt`, `02-test.txt`, `03-exposure.txt`, `04-mitigation.txt`, `05-cleanup.txt`, and the embedded screenshot `03-exposure.png` | not published | 2026-11-04 | Demonstrated |
| 40 | Lab captures for CVE-2026-96655: `plan.json`, `01-setup-attempt1-collision.txt`, `01-setup.txt`, `02-test.txt`, `03-exposure.txt`, `04-mitigation.txt`, `05-cleanup.txt`, and the embedded screenshots `03-exposure.png` and `05-cleanup.png` | not published | 2026-11-04 | Demonstrated |
| 41 | Lab captures for CVE-2026-96656: `plan.json`, `01-setup.txt`, `02-test.txt`, `03-exposure.txt`, `04-mitigation.txt`, `05-cleanup.txt`, and the embedded screenshot `04-mitigation.png` | not published | 2026-11-04 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md): no actor or malware family is attributed to this exploitation
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Triage a CVE](/guides/TRIAGE_A_CVE.md)
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Homelab Setup](/HOMELAB_SETUP.md)
- Other lab-backed studies: [Ghostcat](/case-studies/GHOSTCAT_CVE_2020_1938.md), the Tomcat AJP file read in the lab; [ProFTPD mod_copy](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md); [Magento and Adobe Commerce PolyShell](/case-studies/MAGENTO_CVE_2026_48356.md); [Node.js Brotli decoder](/case-studies/NODEJS_CVE_2026_111497.md), another version check that tells a vulnerable build from a fixed one; [PHP 8.4.27](/case-studies/PHP_8_4_27_CVES.md), the interpreter flaws CISA calls php2shell; [Collabora Built-in CODE Server in Nextcloud](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md), another self-hosted server exploited before most owners had read an advisory
- Other vulnerability studies: [PHP2Shell and the October 2026 attack wave](/case-studies/PHP2SHELL_OCTOBER_2026.md), which records the Plex KEV additions in the same week; [Log4Shell](/case-studies/LOG4SHELL.md), where a logging feature became a remote fetch; [the Linux TCP use-after-free, CVE-2026-98432](/case-studies/LINUX_TCP_UAF_2026.md); [AI Threats 2026](/case-studies/AI_THREATS_2026.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1528 Steal Application Access Token](/mitre/techniques/T1528.md), [T1129 Shared Modules](/mitre/techniques/T1129.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1496.001 Compute Hijacking](/mitre/techniques/T1496-001.md), [T1496.002 Bandwidth Hijacking](/mitre/techniques/T1496-002.md), [T1059.004 Unix Shell](/mitre/techniques/T1059-004.md)
- CAPEC: [CAPEC-664 Server Side Request Forgery](/mitre/capec/CAPEC-664.md), [CAPEC-76 Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md)
- D3FEND: [Software Update](/mitre/d3fend/software-update.md), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), [Disable Remote Access](/mitre/d3fend/disable-remote-access.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md), [all countermeasures](/mitre/d3fend/README.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [plex-media-server-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/plex-media-server-2026.json)
- [All case studies](/case-studies/README.md)
