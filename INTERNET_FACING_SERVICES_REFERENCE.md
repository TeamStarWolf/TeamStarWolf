# Internet-Facing Services and External Exposure

This reference catalogs the services an enterprise commonly exposes to untrusted networks, what each one is for, why it is risky when reachable from the internet, how an attacker abuses it, and how to find and reduce the exposure. It is written for a vulnerability management analyst who owns the external attack surface and has to decide what should be reachable at all before deciding what to patch.

| Attribute | Value |
|---|---|
| Scope | Network services, protocols, web servers, and edge appliances exposed externally |
| Lens | Should this be reachable, then is it vulnerable, then is it exploited |
| Finding link | Scanner findings, CTEM discovery, external attack surface management |
| Identity | Port and protocol, service and version, `CVE`, `CWE` |

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management and network security analysts who own the external attack surface

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,233 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to decide what should be reachable from the internet before deciding what to patch, you are hunting exposed management or database services, or you are prioritizing internet-facing appliance findings

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[How to find your external exposure](#how-to-find-your-external-exposure), [Services that should rarely be internet-facing](#services-that-should-rarely-be-internet-facing), [Hardening and reducing attack surface](#hardening-and-reducing-attack-surface)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Scanner Platforms and Findings Catalog](SCANNER_PLATFORMS_REFERENCE.md), [Edge Device Security Reference](EDGE_DEVICE_SECURITY_REFERENCE.md), [Network Defense Reference](NETWORK_DEFENSE_REFERENCE.md), [CTEM Reference](CTEM_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What counts as internet-facing

An internet-facing asset is anything that answers an unauthenticated connection from the public internet: a web server, a VPN gateway, a mail server, an exposed management port, a forgotten cloud instance with a public IP. The external attack surface is the full set of these, including the ones nobody meant to publish. Shadow and forgotten assets, not the well-known web farm, are where most external compromise starts.

## How to find your external exposure

You cannot patch what you have not found, so discovery comes before assessment.

- Internet-wide scan data: services such as Shodan and Censys index reachable hosts; querying your own address space and certificates surfaces assets your inventory missed.
- Authenticated cloud inventory: enumerate public IPs, load balancers, and security groups across every cloud account and region, because a public IP on a new subnet is the common gap.
- External vulnerability scans: an unauthenticated scan from outside the perimeter shows what an attacker sees; pair it with credentialed internal scans for depth. See [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).
- Continuous discovery: external attack surface management (EASM) and the discovery stage of exposure management keep the inventory current rather than point-in-time. See [CTEM Reference](/CTEM_REFERENCE.md).

## Services that should rarely be internet-facing

These are management, file, and directory services meant for internal networks. When they appear on a public IP it is almost always a misconfiguration, and each is a recurring breach cause.

| Service | Port | Why exposure is dangerous |
|---|---|---|
| SMB / CIFS | `445` | File sharing and remote Windows access; the vector for WannaCry and NotPetya through `CVE-2017-0144` (EternalBlue). Never expose it. |
| RDP | `3389` | Remote desktop; brute force, credential stuffing, and pre-auth flaws make it a top ransomware entry point. Put it behind a VPN or a gateway with multi-factor authentication. |
| NetBIOS / RPC | `137` to `139`, `135` | Legacy Windows name and procedure calls; leak host and user information and expose exploitable services. |
| LDAP / LDAPS | `389`, `636` | Directory access; unauthenticated binds and injection leak the directory. Keep it internal. |
| SNMP | `161` | Device management; default community strings (`public`, `private`) and version 1 or 2c leak and alter configuration. Use version 3 and keep it internal. |
| Databases | `3306`, `5432`, `1433`, `1521`, `27017`, `6379` | MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, and Redis should never face the internet; exposed and default-credentialed databases are a mass-breach pattern. |
| Kerberos, WinRM, VNC, Telnet | `88`, `5985`, `5900`, `23` | Authentication, remote management, and remote control; Telnet and VNC are cleartext or weakly authenticated. |

For each, the finding to act on first is the exposure itself. Removing the reachability closes the risk faster than patching the service in place.

## Services commonly exposed by design

These are meant to be reachable, so the work is hardening and patching rather than removal.

- HTTP and HTTPS (`80`, `443`): the web surface. Redirect `80` to `443`, enforce modern TLS, and treat the application behind it with the full application security program. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- SMTP (`25`, `465`, `587`): mail transport. Lock down relaying, enforce TLS, and deploy SPF, DKIM, and DMARC against spoofing. See [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md).
- DNS (`53`): name resolution. Separate authoritative from recursive servers, restrict zone transfers, prevent open resolvers used in amplification, and consider DNSSEC.
- SSH (`22`): remote administration. Require keys or certificates, disable password and root login, and restrict source addresses; prefer a bastion over direct exposure.
- FTP and SFTP (`21`, `22`): file transfer. Plain FTP is cleartext and should be retired for SFTP or FTPS; anonymous FTP leaks files.

## Web server technologies

The web server behind an exposed port is itself an asset to inventory, version, and patch.

- Apache HTTP Server (`httpd`): configuration-driven; risky patterns include directory listing, exposed `.htaccess` or `.git` directories, outdated modules, and mod_proxy misconfiguration behind reverse proxies.
- Nginx: common as a web server and reverse proxy; watch for misrouted `location` blocks, missing security headers, and proxy misconfiguration that exposes internal services.
- Microsoft IIS: watch for outdated versions, exposed management endpoints, and legacy ASP handlers.
- Application servers (Apache Tomcat, JBoss, WebLogic, WebSphere): the exposed manager or admin consoles and deserialization flaws in these are a recurring critical-finding source. Keep management interfaces off the internet.

Across all of them, remove version banners where practical, set security headers, disable unused modules and methods, and keep the server and its runtime patched.

## Load balancers, reverse proxies, and edge appliances

Load balancers and reverse proxies sit at the perimeter, terminate TLS, and route to back ends. Security appliances (VPN concentrators, firewalls, application delivery controllers) sit in the same position. That position makes them high-value and makes their vulnerabilities severe: a flaw in the device that fronts everything is a flaw in front of everything.

- The recurring pattern: edge and appliance products (for example application delivery controllers, VPN gateways, and firewalls) have produced a steady stream of pre-authentication, actively exploited vulnerabilities that land on the CISA Known Exploited Vulnerabilities catalog within days. Treat any KEV entry for an internet-facing appliance as an emergency.
- Inventory every appliance with its exact firmware version, because these devices are often outside the normal patch and agent coverage and go stale.
- Terminate and configure TLS correctly at the load balancer, and make sure it does not forward to an unpatched or unauthenticated back end.
- Prioritize appliance findings above general server findings when the device is internet-facing, using exploitation signals. See [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) and [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md).

## Detecting vulnerable exposed services

- Run unauthenticated external scans to enumerate open ports, service versions, and TLS configuration, then credentialed scans to confirm patch level.
- Reconcile scanner output to one asset so the same exposed host reported by several tools is counted once. See [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).
- Verify exposure from outside your own network, since an internal scan can reach services a firewall actually blocks from the internet, giving a false sense of exposure or safety.

## Hardening and reducing attack surface

The order that reduces risk fastest:

1. Remove reachability: take management, file, directory, and database services off public IPs and behind a VPN or zero-trust gateway.
2. Patch what must stay exposed, appliances and edge devices first, driven by known exploitation.
3. Enforce strong authentication (multi-factor, keys, certificates) on everything that remains reachable.
4. Enforce transport security (modern TLS, no cleartext protocols).
5. Monitor the external surface continuously so new exposure is caught in hours, not at the next quarterly scan.

See [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md) and [Zero Trust Reference](/ZERO_TRUST_REFERENCE.md) for the architecture that keeps these services off the open internet in the first place.

## Learning resources

- Map each exposed service to its hardening guidance in the platform references cited above, and to the CIS Benchmarks for the specific product.
- For the appliance and edge pattern, track the CISA Known Exploited Vulnerabilities catalog and treat internet-facing entries as time-critical. See [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Network security](/hubs/network-security.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [CTEM Reference](/CTEM_REFERENCE.md)

<!-- related:end -->
