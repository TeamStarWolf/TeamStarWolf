# Host a Secure Static Site on Your Own Domain with Cloudflare and GitHub Pages

> By the end of this guide you will have a static site served over HTTPS on a domain you own, with GitHub Pages as the origin, Cloudflare in front of it for DNS, TLS settings and real security headers, the domain verified against takeover, and a written rollback for every step. Everything in it uses free tiers; the only cost is the domain.

| Time | Difficulty | You need | You'll produce |
|---|---|---|---|
| About 2 hours, most of it waiting for DNS and certificates | Beginner to intermediate | A GitHub repository that already publishes a Pages site, a Cloudflare account with two-factor authentication on, about $10 a year for a domain, a terminal with curl (the GitHub CLI is optional) | A live site at `https://example.com/` and `https://www.example.com/`, a Cloudflare zone with the records and settings below, response headers that scanners rate well, and a rollback that returns the site to its github.io address in minutes |

This guide is for anyone who publishes a static site from a repository and wants it on their own name without giving up the free hosting: a personal site, documentation, a project page, a reference library. It is the procedure this library's own front door was set up with, generalized to placeholders. Replace `example.com` with your domain, `your-account.github.io` with your GitHub Pages host, and `OWNER/REPO` with the repository that publishes the site.

Two ideas carry the whole guide. GitHub Pages stays the **origin**: it builds and serves the files, and it issues the certificate for your domain. Cloudflare holds the **zone**: it answers DNS for the name and, once you turn the proxy on, sits between visitors and the origin, which is where TLS policy, caching and response headers come from. You can stop after Step 4 with a working HTTPS site, or continue through Step 6 for the headers GitHub Pages cannot send.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Anyone who publishes a static site from a repository and wants it on their own domain with HTTPS, security headers and a rollback

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,123 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You own or are about to buy a domain for a GitHub Pages site, you want Cloudflare in front of it for TLS policy and response headers, or you need to know which step breaks the certificate and how to undo each change

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Step 3: Add the records that point at GitHub Pages](#step-3-add-the-records-that-point-at-github-pages), [Step 6: Add the response headers GitHub Pages cannot send](#step-6-add-the-response-headers-github-pages-cannot-send), [Verification checklist](#verification-checklist)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Cloud Network Security](/CLOUD_NETWORK_SECURITY.md), [Threat Model an Application](/guides/THREAT_MODEL_AN_APPLICATION.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## At a glance

| Layer | Who does it | What it gives you |
|---|---|---|
| Domain and DNS | Cloudflare Registrar and Cloudflare DNS | The name, the records that point at GitHub, DNSSEC |
| Origin | GitHub Pages | The files, the build, the origin certificate for your domain |
| Edge (optional) | Cloudflare proxy | TLS settings, HSTS, security headers, caching, DDoS absorption, request analytics without a script |
| Verification | GitHub account settings | Proof that you own the domain, so nobody can claim it on Pages if your site is ever removed |

## Before you start

- Your repository publishes a Pages site today at `https://your-account.github.io/REPO/` (a project site) or `https://your-account.github.io/` (a user or organization site). Note which one it is: it changes Step 8.
- Two-factor authentication is on for the Cloudflare account and the GitHub account. The account that holds the domain holds the site; protect it first.
- You can run `curl -sI https://your-account.github.io/REPO/` and see `HTTP/2 200`. If you cannot, fix the site before moving it.
- Decide the names: the apex `example.com`, `www.example.com`, and any subdomains for other sites you publish.

## Step 1: Register the domain and put the zone on Cloudflare

1. Sign in to Cloudflare, open **Domain Registration**, search the name and register it. Registrar pricing is at cost, usually about $10 a year for a `.com`. Registration creates the zone on the Free plan with Cloudflare's nameservers assigned.
2. If the name is registered elsewhere, add it as a site in Cloudflare instead. If DNSSEC is on at the current provider, turn it off (remove the DS record at the registrar) and wait for the DS record's TTL to expire before changing nameservers, or the domain fails to resolve during the move [10]; you re-enable it on Cloudflare in Step 5. Then change the nameservers at the current registrar to the two Cloudflare gives you. Propagation takes minutes to a day.
3. Check: `nslookup -type=NS example.com` shows two names ending in `ns.cloudflare.com`. The zone's **Overview** page says **Active**.

What success looks like: the page says the zone is active, and DNS, Records shows an empty record list for a newly registered domain. For a moved domain, Cloudflare imports the existing records: check that the MX, TXT and other service records match what the old provider served before you change the nameservers, or mail and other services break.

## Step 2: Verify the domain on your GitHub account

GitHub recommends verifying the domain before adding it to a repository, to avoid takeover attacks [1]. Do it before the records in Step 3 exist: once the domain resolves to GitHub, an unverified name can be claimed by any Pages site until you associate it with yours. Without verification, if your repository is ever deleted or Pages is turned off while the DNS records still point at GitHub, someone else can create a Pages site that claims your domain. Verification closes that.

1. GitHub: your profile or organization **Settings**, **Pages**, **Add a domain**: enter `example.com`. GitHub shows a TXT record: name `_github-pages-challenge-ACCOUNT`, value a long token.
2. Cloudflare: DNS, Records, **Add record**: type TXT, name `_github-pages-challenge-ACCOUNT`, content the token, **Save**.
3. Back in GitHub, **Verify**. The domain shows as verified; it also covers the domain's immediate subdomains, such as `www.example.com` and `docs.example.com` [3].

Check: `nslookup -type=TXT _github-pages-challenge-ACCOUNT.example.com 1.1.1.1` shows the token.

## Step 3: Add the records that point at GitHub Pages

GitHub documents four IPv4 and four IPv6 addresses for apex domains and a CNAME for `www`. Add them with **Proxy status OFF** (grey cloud, "DNS only") for now: GitHub must see your domain resolve to its own addresses to issue the certificate in Step 4.

| Type | Name | Content | Proxy |
|---|---|---|---|
| A | @ | 185.199.108.153 | DNS only |
| A | @ | 185.199.109.153 | DNS only |
| A | @ | 185.199.110.153 | DNS only |
| A | @ | 185.199.111.153 | DNS only |
| AAAA | @ | 2606:50c0:8000::153 | DNS only |
| AAAA | @ | 2606:50c0:8001::153 | DNS only |
| AAAA | @ | 2606:50c0:8002::153 | DNS only |
| AAAA | @ | 2606:50c0:8003::153 | DNS only |
| CNAME | www | your-account.github.io | DNS only |

In the dashboard: DNS, Records, **Add record**, pick the type, type `@` or `www` as the name, paste the content, switch the proxy toggle off, **Save**. Nine times. For a domain moved in Step 1, first delete the imported apex `A` and `AAAA` records and any `www` record that point at the previous host: the apex must resolve only to GitHub's four addresses, or the DNS check in Step 4 fails and visitors split between the old host and the new one. The dashboard will warn that proxying is recommended; ignore it until Step 5.

Check: `nslookup example.com 1.1.1.1` returns the four A records; `nslookup -type=CNAME www.example.com 1.1.1.1` returns `your-account.github.io`. Public DNS usually shows them within ten minutes.

## Step 4: Set the custom domain on GitHub Pages and enforce HTTPS

1. In the repository: **Settings**, **Pages**, **Custom domain**: enter `example.com` and **Save**. GitHub runs a DNS check, then requests a certificate from Let's Encrypt for the apex and, if the `www` record already exists, for `www` as well.
2. From a terminal, the same thing: `gh api -X PUT repos/OWNER/REPO/pages -f cname=example.com`.
3. Wait. The Pages settings page shows "DNS check successful", then the certificate status moves to approved; in practice one to fifteen minutes. From a terminal: `gh api repos/OWNER/REPO/pages --jq '.https_certificate.state'` prints `approved`.
4. Tick **Enforce HTTPS**, or run `gh api -X PUT repos/OWNER/REPO/pages -F https_enforced=true`.
5. Checks: `curl -sI https://example.com/` returns `HTTP/2 200` with `server: GitHub.com`; `curl -sI https://your-account.github.io/REPO/` returns `301` with `location: https://example.com/`; `curl -sI http://example.com/` returns `301` to HTTPS.

Two things to know. If you add the `www` record after GitHub issued the certificate, the certificate covers only the apex; re-save the custom domain to make GitHub request one that covers both. And for a **project** site, the custom domain serves the site at the domain root: `https://example.com/` now shows what `https://your-account.github.io/REPO/` showed, and the old address redirects. Any absolute links in your content that still name the old address keep working through that redirect, and deserve a cleanup commit. If the site is built with a base path of `/REPO/` (a static-site generator's base URL, or asset links written as `/REPO/...`), rebuild it with base `/` before or at the switch: the homepage returns 200 at the apex while scripts and styles requested from `/REPO/` return 404.

What success looks like: the site opens on your domain with a valid padlock, and the old address bounces to it.

## Step 5: Turn on the proxy and set the TLS policy

Now that the origin holds a valid certificate, let Cloudflare sit in front.

1. First check **SSL/TLS**, **Edge Certificates**: the Universal SSL certificate for `example.com` and its first-level subdomains shows **Active**. Cloudflare provisions it within fifteen minutes to twenty-four hours of the zone activating, even while the records are DNS only, and presents it only once the records are proxied [13]; proxying before it is active sends visitors to an edge that cannot yet serve a valid certificate. Then DNS, Records: edit each of the nine records and switch **Proxy status** to **Proxied** (orange cloud).
2. **SSL/TLS**, **Overview**: encryption mode **Full (strict)**. This makes Cloudflare validate the origin's certificate, which GitHub has just issued, so there is no plaintext hop and no unvalidated hop.
3. **SSL/TLS**, **Edge Certificates**: **Always Use HTTPS** on; **Minimum TLS Version** 1.2; **Automatic HTTPS Rewrites** on if your content ever had `http://` links.
4. **HSTS**: do not enable it on the first day. Run the site over HTTPS for a week, check that every subdomain you use also serves HTTPS, then enable HSTS with a short `max-age`, and raise it to a year only when you are sure. The dashboard setting offers one to twelve months, so its shortest trial is one month [8]; for a one-day trial (`max-age=86400`), set the `Strict-Transport-Security` header yourself in the Transform Rule of Step 6 instead, and leave the dashboard setting off until you commit. `includeSubDomains` and preload are commitments that are hard to undo: a wrong one can make a subdomain unreachable for the whole max-age, and preload lists require a max-age of at least twelve months [8].
5. **DNS**, **Settings**: enable **DNSSEC**. With Cloudflare Registrar the DS record is set for you; with another registrar, copy the DS record there.
6. CAA: optional. If you add CAA records, they must allow the authorities GitHub and Cloudflare use (Let's Encrypt for the origin; Cloudflare's own authorities for the edge certificate, listed in its documentation), or renewals fail silently later.

Checks: `curl -sI https://example.com/` now shows `server: cloudflare` and a `cf-ray` header; the padlock still validates; `https://www.ssllabs.com/ssltest/` grades the apex A or better.

What success looks like: the site serves from Cloudflare's edge, Full (strict) is selected, and the SSL Labs report shows TLS 1.2 and 1.3 only.

## Step 6: Add the response headers GitHub Pages cannot send

GitHub Pages sends no `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options` or `Referrer-Policy` header. A `<meta http-equiv>` tag can carry a CSP but cannot express `frame-ancestors`. Cloudflare's Transform Rules add headers to every response that passes through the proxy.

1. **Rules**, **Transform Rules**, **Modify Response Header**, **Create rule**. Name it `security-headers`. Match: all incoming requests (or hostname equals `example.com`).
2. Add these headers with **Set static**:

| Header | Value | What it does |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | Only your own files may run or load; nothing may frame the site. Loosen one source at a time if a page breaks. |
| `X-Content-Type-Options` | `nosniff` | Browsers trust the declared content type |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Other sites see your origin, not your paths |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` | Device features are off by default |
| `X-Frame-Options` | `DENY` | The legacy framing control, for older browsers |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates your window from cross-origin openers |

3. Deploy the rule. Open the site, then the browser console: a CSP violation prints as a console error naming the blocked source. Fix the page or add the exact source; never add `'unsafe-inline'` to get past an error, because that gives up most of what the policy buys.
4. Checks: `curl -sI https://example.com/ | grep -i -E "content-security|nosniff|referrer|permissions|frame"` shows all of them; `https://securityheaders.com/` grades the site A; the Mozilla Observatory gives a second opinion.

If your site loads a script, style or font from a third-party host, that host must appear in the matching CSP directive, and you have just made that host part of your trust boundary. Self-hosting the file is the smaller surface.

## Step 7: Caching and the deploy-skew window

Cloudflare caches static files at the edge, and GitHub Pages sets a ten-minute `Cache-Control` on its own. Cloudflare's **Browser Cache TTL** defaults to four hours and overrides an origin lifetime shorter than itself, so set **Caching**, **Configuration**, **Browser Cache TTL** to **Respect Existing Headers** first; otherwise repeat visitors keep scripts and styles for four hours [14]. With that set, two consequences:

- After a deploy, some visitors see the old page for up to ten minutes. For a documentation site that is fine. For an app that loads data files and checks them against a manifest, give each data file URL the manifest's own hash as a query string so a new manifest always fetches a new file, and retry once past the cache when a check fails.
- If you want an edit live at once, **Caching**, **Configuration**, **Purge Everything**, or purge the single URL.

A **Cache Rule** can shorten or lengthen edge caching per path. Leave the defaults until you have a reason.

## Step 8: Subdomains for other sites you publish

A custom domain set on a user or organization site covers every project site on that account, at `example.com/REPO/`. A custom domain set on a **project** site covers only that project. Any other project site can get its own name:

1. Cloudflare: add `CNAME docs` (or any label) pointing at `your-account.github.io`, DNS only.
2. GitHub: in that repository's Pages settings, custom domain `docs.example.com`; wait for the certificate; enforce HTTPS.
3. If the site is a single-page application built with a base path such as `/REPO/`, rebuild it with base `/` before the switch, or its assets will 404 on the new name.
4. Proxy the record and the Transform Rule from Step 6 applies to it as well, if the rule matches all hostnames.

## What GitHub Pages cannot do, and when to go further

GitHub Pages serves files: a 1 GB site, a soft 100 GB a month, ten builds an hour, deployments that time out at ten minutes, no server-side code and no custom headers from the origin. With Cloudflare in front, that is enough for most static sites.

When you need a little server-side logic (a form endpoint, an API that reads a database, a scheduled job), Cloudflare Workers or Pages Functions run it on the same free plan up to 100,000 requests a day, with KV, D1 and R2 for state. When you need a long-running process, a non-HTTP listener, or software that must be self-hosted, you need a virtual server, and that is a different guide. A honeypot or any deliberately exposed listener never belongs on the host or in the zone that serves your site; it gets its own isolated host and network.

## Pitfalls

- **Proxy on before the certificate.** GitHub's DNS check sees Cloudflare's addresses, not its own, and never issues the certificate. Keep the records DNS only until Step 4 passes.
- **`www` added late.** The origin certificate covers only the apex; re-save the custom domain.
- **Forgetting verification.** Step 2 is five minutes and prevents a takeover that is otherwise silent.
- **HSTS with preload on day one.** If a subdomain is not on HTTPS, it becomes unreachable for the full max-age, and preload lists are slow to leave.
- **A CSP copied from a blog.** Start closed, open one directive at a time, and read the console.
- **Scanning the wrong thing.** The servers behind your domain belong to GitHub and Cloudflare. Passive checks (TLS, headers, DNS) are fine; port scans, active exploitation tools and load tests against them are not yours to run.
- **A single-page app on a subdomain** with the old base path. Rebuild with base `/`.

## Verification checklist

- [ ] `nslookup -type=NS example.com` shows Cloudflare nameservers.
- [ ] The nine records exist; the apex resolves to the four GitHub addresses.
- [ ] The domain is verified on the GitHub account (TXT record present).
- [ ] GitHub Pages shows the certificate approved and Enforce HTTPS ticked.
- [ ] `https://example.com/` and `https://www.example.com/` return 200; the github.io address returns 301.
- [ ] Edge certificate Active before the proxy went on; proxy on; Full (strict); Always Use HTTPS; minimum TLS 1.2; DNSSEC enabled; Browser Cache TTL set to Respect Existing Headers.
- [ ] The security headers appear in `curl -sI`; securityheaders.com grades A; SSL Labs A or better.
- [ ] HSTS enabled only after a week of clean HTTPS, with a short max-age first.

## Rollback

- To leave Cloudflare's edge but keep the domain: switch the nine records back to DNS only. The site serves straight from GitHub Pages with its own certificate; the Transform Rule stops applying.
- To return to the github.io address: in the repository's Pages settings, remove the custom domain. The old address serves the site again within minutes. A project site you rebuilt with base `/` in Step 4 needs its base path of `/REPO/` back at the same time, or its scripts and styles return 404 at the old address. Leave the DNS records in place until you decide what the domain should do next, and keep the verification record.
- To undo HSTS: set the max-age to 0 in the same rule or setting, and wait out the previous max-age on clients that already saw it. This is why the first max-age is short.

## Sources

| # | Source | Opened | Grade |
|---|---|---|---|
| 1 | GitHub Docs, About custom domains and GitHub Pages: https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/about-custom-domains-and-github-pages | 2026-11-12 | Confirmed |
| 2 | GitHub Docs, Managing a custom domain for your GitHub Pages site (the A, AAAA and CNAME records): https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site | 2026-11-12 | Confirmed |
| 3 | GitHub Docs, Verifying your custom domain for GitHub Pages: https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages | 2026-11-12 | Confirmed |
| 4 | GitHub Docs, Securing your GitHub Pages site with HTTPS: https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https | 2026-11-12 | Confirmed |
| 5 | GitHub Docs, GitHub Pages limits: https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits | 2026-11-12 | Confirmed |
| 6 | GitHub REST API, Pages (update information about a GitHub Pages site): https://docs.github.com/en/rest/pages/pages | 2026-11-12 | Confirmed |
| 7 | Cloudflare Docs, Encryption modes (Full (strict)): https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/ | 2026-11-12 | Confirmed |
| 8 | Cloudflare Docs, HTTP Strict Transport Security: https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/ | 2026-11-12 | Confirmed |
| 9 | Cloudflare Docs, Modify response headers with Transform Rules: https://developers.cloudflare.com/rules/transform/response-header-modification/ | 2026-11-12 | Confirmed |
| 10 | Cloudflare Docs, DNSSEC: https://developers.cloudflare.com/dns/dnssec/ | 2026-11-12 | Confirmed |
| 11 | Cloudflare Docs, Workers pricing and limits (free plan requests): https://developers.cloudflare.com/workers/platform/pricing/ | 2026-11-12 | Confirmed |
| 12 | The procedure as performed on 2026-11-11 for this library's domain: certificate approved about one minute after the custom domain was set, the old address redirecting 301, the `www` certificate missing because its record was added after issuance | 2026-11-11 | Confirmed |
| 13 | Cloudflare Docs, Enable Universal SSL certificates: https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/enable-universal-ssl/ | 2026-11-13 | Confirmed |
| 14 | Cloudflare Docs, Edge and Browser Cache TTL: https://developers.cloudflare.com/cache/how-to/edge-browser-cache-ttl/ | 2026-11-13 | Confirmed |

## Related references

- [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md)
- [Cloud Network Security](/CLOUD_NETWORK_SECURITY.md)
- [Cloud Architecture Reference](/CLOUD_ARCHITECTURE_REFERENCE.md)
- [Harden a Linux Host](/guides/HARDEN_A_LINUX_HOST.md), for the server you may add later
- [Threat Model an Application](/guides/THREAT_MODEL_AN_APPLICATION.md), before you add server-side code
