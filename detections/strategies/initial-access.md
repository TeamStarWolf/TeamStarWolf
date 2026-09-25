# Initial Access — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Initial Access**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1189 — Drive-by Compromise
<a id="t1189"></a>

**Detection strategy:** Drive-by Compromise — Behavior-based, Multi-platform Detection Strategy (T1189) (`DET0176`)  
**Platforms:** Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1189](https://attack.mitre.org/techniques/T1189/) · [detail page](../../techniques/initial-access.md#t1189)

- **`AN0498` Analytic 0498** · Windows
  Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file drops. Defender sees network requests to previously unseen/suspicious domains or resources + browser process spawning unusual children or loading unsigned modules + file writes or registry changes shortly after those requests.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Application` (Browser or plugin/application logs showing script errors, plugin enumerations, or unusual extension load events); `etw:Microsoft-Windows-Kernel-Process` (Memory Modification / Unmapped module load or suspicious RWX allocations in the process space of a browser process); `WinEventLog:Sysmon` (EventCode=11); `NSM:Flow` (http.request: HTTP requests and responses for specific script resources, unexpected content-types (application/octet-stream for script URLs), suspicious referrers, or obfuscated javascript resources)
  - *Tune:* `TimeWindow` — Correlation time window between suspicious network fetch and subsequent process/file events. Tweak for environment latency and caching; default 2 minutes.; `KnownGoodDomainsList` — Allowlist of high-volume, benign domains used by corporate sites or CDNs to reduce false positives.; `PayloadEntropyThreshold` — Entropy threshold for downloaded script/binary content to surface likely obfuscated/packed payloads.; `UserContext` — Exclude or treat differently known administrative service accounts or build machines versus end-user contexts.
- **`AN0499` Analytic 0499** · Linux
  Correlated evidence of browser or webview fetches to uncommon domains or mutated JS resources (proxy/NGFW logs + Zeek/HTTP logs) followed by unexpected interpreters or script engines executing (python, ruby, sh) spawned from browser processes or user sessions, rapid on-disk staging in /tmp, and outbound connections that deviate from baseline. Defender sees: uncommon resource fetch → short-lived child process executions from user browser context → file writes in temp directories → anomalous outbound C2-like connections.
  - *Log sources:* `auditd:SYSCALL` (execve: execve calls where a browser/webview process is parent and child is interpreter (python, sh, ruby) or downloader (curl, wget)); `linux:syslog` (Application or browser logs (webview errors, plugin enumerations) indicating suspicious script evaluation or plugin loads); `NSM:Flow` (http::response: HTTP responses with suspicious content-type for scripts, long obfuscated javascript bodies, or redirects to exploit kit domains); `linux:Sysmon` (New files in /tmp, /var/tmp, $HOME/.cache, executed within TimeWindow after browser HTTP fetch); `NSM:Connections` (Outbound connections from newly spawned child processes or from the browser to uncommon endpoints or on anomalous ports)
  - *Tune:* `TempPathPatterns` — Paths used for staging differ by distro and package manager; tune to include company-specific temp paths or exclude known benign build machines.; `UserShellWhitelist` — Whitelist known server/service accounts or CI/CD runners where shell executions are expected.; `DomainRarityThreshold` — Threshold for flagging domains based on internal popularity vs global rarity.
- **`AN0500` Analytic 0500** · macOS
  Correlated evidence where Safari/Chrome/WebKit-based processes issue network requests for uncommon or obfuscated JS resources followed by spawning of script interpreters, launchd or ad-hoc binaries, unusual child processes, or dynamic library loads into browser processes. Defender sees: proxy/HTTP logs with suspicious resource content + unifiedlogs/ASL showing browser/plugin crashes or extension loads + process events indicating child process creation and file writes to /var/folders or /tmp shortly after the fetch.
  - *Log sources:* `macos:unifiedlog` (Logs from unifiedlogging that show browser crashes, plugin enumerations, extension installs or errors around the same time as suspicious network fetches); `macos:unifiedlog` (process_create: Process creation where parent is Safari/Google Chrome and child is script interpreter or signed-but-unusual helper binary); `macos:unifiedlog` (New files written to /var/folders, /tmp, ~/Library/Caches, or ~/Downloads by browser context or its children); `NSM:Flow` (HTTP/HTTPS requests for script resources flagged by content inspection (excessive obfuscation, eval usage, unusual redirects)); `macos:unifiedlog` (Anomalous dyld dynamic library loads or RWX memory mappings in browser process)
  - *Tune:* `SleepyUserThreshold` — Volume thresholds for interactive user browsing vs. automated systems (e.g., shared kiosks) — tune to reduce FP in heavy-browsing employees.; `ExtensionInstallPolicy` — Policy setting that influences how extension installs are treated: strict policy reduces FP from known extension behavior.
- **`AN0501` Analytic 0501** · Identity Provider
  Post-compromise identity & session anomalies that follow a drive-by compromise: token reuse from new/unfamiliar IPs, anomalous sign-in patterns for previously inactive users, unexpected consent/grant events, or provisioning changes. Defender sees an endpoint/browser compromise (network + endpoint signals) followed by unusual IdP events: new refresh token issuance, consent/consent-grant events, odd MFA bypass patterns, or unusual OAuth client registrations.
  - *Log sources:* `azure:signinlogs` (SignIn: Sign-ins flagged as atypical (new geographic region, unfamiliar device id) shortly after correlated endpoint/browser compromise times); `m365:unified` (Application Consent grants, new OAuth client registrations, or unusual admin-level activities executed by a user account shortly after suspected drive-by compromise); `saas:auth` (Refresh token issuance or refresh token usage from new IPs or user agents); `AWS:CloudTrail` (ConsoleLogin: If IdP backed by cloud provider, Console login from new IP/agent after correlated endpoint compromise)
  - *Tune:* `IdpAlertWindow` — Time window to correlate IdP events to endpoint compromise alerts (default 30 minutes to 2 hours).; `HighRiskCountryList` — List of countries/IP zones considered high risk for sign-ins; used to tune geo-anomalies.; `DeviceTrustLevel` — Device trust scoring thresholds that influence whether a sign-in is considered suspicious.

---

### T1190 — Exploit Public-Facing Application
<a id="t1190"></a>

**Detection strategy:** Exploit Public-Facing Application – multi-signal correlation (request → error → post-exploit process/egress) (`DET0080`)  
**Platforms:** Containers, ESXi, IaaS, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/) · [detail page](../../techniques/initial-access.md#t1190)

- **`AN0219` Analytic 0219** · Windows
  Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other service) spawns shell/LOLbins or loads non-standard modules → (4) optional outbound callback from the host/container.
  - *Log sources:* `ApplicationLog:IIS` (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `PublicVIPs` — List of public IPs/hostnames that front apps; used to scope web log and Zeek/proxy data.; `SuspiciousPatterns` — Regex set for exploit-like inputs (../, union select, cmd=, ${jndi:, rO0AB (Java serialization), %00, ${env:}, ${${::-j}ndi}).; `ErrorRateThreshold` — Spike threshold for HTTP status 5xx/4xx per client or URI (e.g., >5 in 5m).; `TimeWindow` — Correlation horizon between request, error, process spawn, and egress (e.g., 15 minutes).; `AllowedChildList` — Known child processes of app pools (e.g., msbuild.exe in CI) to reduce false positives.
- **`AN0220` Analytic 0220** · Linux
  Adversary exploits Apache/Nginx/app servers. Chain: (1) suspicious requests in access logs → (2) spike of 5xx or WAF blocks → (3) web server or interpreter (apache2/nginx/php-fpm/node/python) spawns /bin/sh, curl, wget, socat, or writes webshell → (4) outbound callback.
  - *Log sources:* `ApplicationLog:WebServer` (/var/log/httpd/access_log, /var/log/apache2/access.log, /var/log/nginx/access.log with exploit indicators and burst errors); `auditd:SYSCALL` (execve); `NSM:Flow` (HTTP payloads with SQLi/LFI/JNDI/deserialization indicators)
  - *Tune:* `WebProcList` — server/interpreter names to watch (apache2, httpd, nginx, php-fpm, uwsgi, gunicorn, node).; `ChildToolList` — post-exploitation binaries (sh, bash, curl, wget, python, perl, socat, nc).; `BurstThreshold` — Rate of errors/requests per src_ip/uri to flag reconnaissance/exploit spray.; `TimeWindow` — Exec/network correlation window.
- **`AN0221` Analytic 0221** · macOS
  Adversary targets macOS-hosted public services (e.g., nginx, node). Chain: suspicious inbound request → service crash/5xx → service spawns shell or writes file → new outbound connection.
  - *Log sources:* `macos:unifiedlog` (App/web server logs ingested via unified logging or filebeat (nginx/apache/node).); `macos:unifiedlog` (exec events where web process starts a shell/tooling); `NSM:Flow` (outbound egress from web host after suspicious request)
  - *Tune:* `ServiceList` — Names/paths of public daemons on macOS (httpd, nginx, node, java).; `TimeWindow` — Correlation window for request → exec → egress.
- **`AN0222` Analytic 0222** · Containers
  Adversary exploits containerized app via ingress or service. Chain: (1) suspicious request in ingress/app logs → (2) container process spawns a shell/exec/sidecar (kubectl exec/docker exec) → (3) egress to Internet or metadata service (169.254.169.254).
  - *Log sources:* `ApplicationLog:Ingress` (Kubernetes NGINX/Envoy ingress controller logs with anomalous payloads and 5xx spikes); `docker:events` (Docker/Kubernetes audit of exec/attach (kubectl exec) or unexpected child processes inside container); `NSM:Flow` (Requests towards cloud metadata or command & control from pod IPs)
  - *Tune:* `IngressNamespaces` — Namespaces that are Internet-facing.; `MetadataEndpoints` — Cloud metadata IPs/hostnames for exfil of credentials.; `TimeWindow` — Join period between ingress request and pod exec/egress.
- **`AN0223` Analytic 0223** · IaaS
  Adversary targets cloud-hosted public endpoints. Chain: (1) ALB/ELB/Cloud LB logs show exploit-like inputs or error spikes → (2) workload spawns shell or reaches metadata API → (3) egress to new external hosts.
  - *Log sources:* `ALB:HTTPLogs` (AWS ALB/ELB/GCP/Azure Application Gateway HTTP logs with unusual methods, long URIs, serialized payloads, 4xx/5xx bursts); `AWS:VPCFlowLogs` (VPC/NSG flow logs for pod/instance egress to Internet or metadata)
  - *Tune:* `LBProjects` — Cloud accounts/subscriptions/regions to include.; `ErrorBurst` — 5xx/4xx per client threshold.
- **`AN0224` Analytic 0224** · ESXi
  Adversary exploits exposed OpenSLP on ESXi or vCenter public endpoints. Chain: inbound request pattern to mgmt service → hostd/vpxd error/crash/restart → unexpected process behavior or datastore access → outbound callback.
  - *Log sources:* `esxi:hostd` (/var/log/hostd.log anomalies (faults, crashes, restarts) around inbound connections); `NSM:Flow` (Connections to TCP 427 (SLP) or vCenter web services from untrusted sources)
  - *Tune:* `MgmtCIDR` — Only trusted admin networks should reach ESXi/vCenter.; `TimeWindow` — Join errors and inbound flows.
- **`AN0225` Analytic 0225** · Network Devices
  Adversary exploits public admin services on routers/firewalls/switches. Chain: anomalous HTTP/SNMP/SmartInstall inputs → device syslog errors/restarts → config changes/CLI spawn → egress to attacker C2.
  - *Log sources:* `networkdevice:controlplane` (Syslog from edge devices with HTTP 500s on mgmt portal, SmartInstall events, unexpected CLI commands); `NSM:Flow` (NetFlow/sFlow for odd egress to Internet from mgmt plane)
  - *Tune:* `MgmtPorts` — List of admin services to watch (8443, 443, 161/udp, 4786, 22).; `TrustedAdmins` — Admin source ranges to allow.

---

### T1195 — Supply Chain Compromise
<a id="t1195"></a>

**Detection strategy:** Behavioral detection for Supply Chain Compromise (package/update tamper → install → first-run) (`DET0537`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1195](https://attack.mitre.org/techniques/T1195/) · [detail page](../../techniques/initial-access.md#t1195)

- **`AN1480` Analytic 1480** · Windows
  1) New or updated software is delivered/installed from atypical sources or with signature/hash mismatches; 2) installer/updater writes binaries to unexpected paths or replaces existing signed files; 3) first run causes unsigned/abnormally signed modules to load or child processes to execute, optionally followed by network egress to new destinations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` (CodeIntegrity reports 'Invalid image hash' or 'Unsigned image' for new/updated binaries); `NSM:Flow` (First-time egress from host after new install to unknown update endpoints)
  - *Tune:* `TimeWindow` — Correlation window between install events and first-run activity (default 2h; adjust for staged rollouts).; `TrustedPublishers` — Publisher/Signer allow-list to suppress expected updates.; `TrustedUpdateHosts` — Known update CDNs/APIs (e.g., download.microsoft.com) to reduce egress false positives.; `RiskScoreThreshold` — Score cut-off for alerting when combining path, signer, and reputation features.
- **`AN1481` Analytic 1481** · Linux
  1) Package manager or curl/wget installs/upgrades from non-approved repos or unsigned packages; 2) new ELF written into PATH directories or replacement of existing binaries/libraries; 3) first run leads to unexpected child processes or outbound connections.
  - *Log sources:* `auditd:SYSCALL` (execve, unlink); `auditd:SYSCALL` (open, rename); `journald:package` (dpkg/apt install, remove, upgrade events); `NSM:Flow` (First-time egress to unknown registries/mirrors immediately after install)
  - *Tune:* `ApprovedRepos` — Allow-listed APT/YUM repo URLs and GPG key fingerprints.; `PathScope` — Directories to watch for new ELF writes (e.g., /usr/bin, /usr/local/bin, /lib*/, /opt/*/bin).; `MinBinarySize` — Ignore tiny helper files; default >16KB.; `TimeWindow` — Install→first-run correlation window (default 2h).
- **`AN1482` Analytic 1482** · macOS
  1) pkg/notarization installs from atypical sources or with Gatekeeper/AMFI warnings; 2) new Mach-O written into /Applications or ~/Library paths or substitution of signed components; 3) first run from installer spawns unsigned children or exfil.
  - *Log sources:* `macos:unifiedlog` (installer or system_installd 'PackageKit: install succeeded/failed' with non-notarized or unknown signer); `macos:osquery` (launchd, processes); `macos:endpointsecurity` (write, rename); `NSM:Flow` (New egress from app just installed to unknown update endpoints)
  - *Tune:* `AllowedTeamIDs` — Apple Developer Team IDs permitted in your fleet.; `TrustedDMGs` — Known DMG/Pkg sources and hashes.; `TimeWindow` — Install→first-run correlation window (default 2h).; `RiskScoreThreshold` — Adjust alert sensitivity based on org tolerance.

---

### T1195.001 — Compromise Software Dependencies and Development Tools
<a id="t1195001"></a>

**Detection strategy:** Supply-chain tamper in dependencies/dev-tools (manager→write/install→first-run→egress) (`DET0009`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1195.001](https://attack.mitre.org/techniques/T1195/001/) · [detail page](../../techniques/initial-access.md#t1195001)

- **`AN0021` Analytic 0021** · Windows
  Adversary manipulates dependencies/dev tools used by developers or CI: a package manager (npm/yarn/pnpm, pip/pipenv, nuget/dotnet, chocolatey/winget, maven/gradle) or a compiler/IDE downloads or restores content; files are written under project paths and execution paths (node_modules, packages, .nuget, .gradle, .m2, %AppData%\npm, %UserProfile%\.cargo\bin, temp build dirs). First run of newly written components triggers scripts (preinstall/postinstall), shell/PowerShell spawning, or loader DLLs, followed by network egress to non-approved registries/CDNs.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` (Invalid/Unsigned image when developer tool launches newly installed binaries); `NSM:Flow` (First-time outbound connections to package registries or unknown hosts immediately after restore/build)
  - *Tune:* `TimeWindow` — Correlate file write by package manager to first execution and egress (default 90 minutes).; `ApprovedRegistries` — Allow-listed registries (e.g., registry.npmjs.org, pypi.org, nuget.org, maven.apache.org, company proxies/CDNs).; `DevHosts` — Limit analytics to engineering endpoints/CI agents to reduce noise.; `TrustedPublishers` — Code-signing publishers acceptable for dev tools.
- **`AN0022` Analytic 0022** · Linux
  Developer or CI invokes package managers/compilers (apt/yum + build-essential, npm/yarn/pnpm, pip/pip3, gem, cargo, go, maven/gradle). These write executable or script files into PATH or project dirs and immediately execute embedded lifecycle hooks (preinstall/postinstall, setup.py, npm scripts) that spawn shells or curl/wget, followed by egress to unfamiliar registries or domains.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (rename, chmod); `journald:package` (dpkg/apt or yum/dnf transaction logs (install/update of build tools)); `NSM:Flow` (First-time egress to new registries/CDNs post-install/build)
  - *Tune:* `ApprovedRepos` — Allowed APT/YUM repos and GPG keys for build tools.; `PathScope` — Monitor /usr/local/bin, /usr/bin, /opt/*/bin, ~/.local/bin, node_modules/.bin, .venv/bin, .cargo/bin, .gradle, .m2.; `TimeWindow` — Default 90 minutes for write→exec→egress linkage.
- **`AN0023` Analytic 0023** · macOS
  Developer tools (Homebrew, pip, npm/yarn, Xcode builds) install or update dependencies; new Mach-O or scripts appear under /usr/local, /opt/homebrew, ~/Library/Application Support, project dirs (node_modules/.bin, venv/bin). First run spawns sh/zsh/osascript/curl and new outbound flows; Gatekeeper/AMFI may flag unsigned components.
  - *Log sources:* `macos:unifiedlog` (softwareupdated/homebrew/install logs, pkginstalld events); `macos:endpointsecurity` (exec); `NSM:Flow` (First-time egress to non-approved registries after dependency install)
  - *Tune:* `AllowedTeamIDs` — Apple Developer Team IDs for approved dev tools (Xcode, JetBrains, etc.).; `BrewTapsAllowList` — Homebrew taps allowed in your environment.; `TimeWindow` — Default 90 minutes.

---

### T1195.002 — Compromise Software Supply Chain
<a id="t1195002"></a>

**Detection strategy:** Compromised software/update chain (installer/write → first-run/child → egress/signature anomaly) (`DET0309`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1195.002](https://attack.mitre.org/techniques/T1195/002/) · [detail page](../../techniques/initial-access.md#t1195002)

- **`AN0862` Analytic 0862** · Windows
  Adversary ships a tampered application or update: an updater/installer (msiexec/setup/update.exe/vendor service) writes or replaces binaries; on first run it spawns scripts/shells or unsigned DLLs and beacons to non-approved update CDNs/hosts. Detection correlates: (1) process creation of installer/updater → (2) file metadata changes in program paths → (3) first-run children and module/signature anomalies → (4) outbound connections to unexpected hosts within a short window.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=6); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` (Unsigned or invalid image for newly installed/updated binaries); `NSM:Flow` (First-time egress to non-approved update hosts right after install/update)
  - *Tune:* `TimeWindow` — Correlate write→first-run→egress (default 90 minutes).; `ApprovedUpdateHosts` — Allow-list of vendor update endpoints, enterprise proxy/cache.; `ApprovedSigners` — Code-signing publishers allowed for programs/services.; `ProgramPaths` — Monitored install locations (e.g., C:\Program Files, C:\ProgramData, %LOCALAPPDATA%).
- **`AN0863` Analytic 0863** · Linux
  A compromised package/update (deb/rpm/tarball/AppImage/vendor updater) is installed, writing/overwriting files in /usr/local/bin, /usr/bin, /opt, or ~/.local; first run executes unexpected shells/curl/wget and connects to unapproved hosts. Correlate package/updater execution → file writes/replace → first-run child processes → egress.
  - *Log sources:* `auditd:SYSCALL` (execve); `journald:package` (dpkg/apt/yum/dnf transaction logs; vendor updaters in systemd journals); `NSM:Flow` (New outbound flows to non-approved vendor hosts post install)
  - *Tune:* `PathScope` — Monitored install paths (/usr/local, /usr/bin, /opt/*, ~/.local/bin, /var/lib/systemd).; `ApprovedRepos` — Allow-listed APT/YUM repos and GPG keys for vendor updates.; `TimeWindow` — Default 90 minutes.
- **`AN0864` Analytic 0864** · macOS
  A tampered app/pkg/notarized update is installed via installer, softwareupdated, Homebrew, or vendor updater; new Mach-O or bundle contents appear in /Applications, /Library, /usr/local or /opt/homebrew; first run spawns sh/zsh/osascript/curl and makes egress to unfamiliar domains; AMFI/Gatekeeper may log signature/notarization problems.
  - *Log sources:* `macos:unifiedlog` (pkginstalld/softwareupdated/Homebrew install transactions); `macos:endpointsecurity` (exec); `NSM:Flow` (New/rare egress to non-approved update hosts after install)
  - *Tune:* `AllowedTeamIDs` — Apple Developer Team IDs allowed for enterprise.; `BrewTapsAllowList` — Trusted Homebrew taps.; `TimeWindow` — Default 90 minutes.

---

### T1195.003 — Compromise Hardware Supply Chain
<a id="t1195003"></a>

**Detection strategy:** Hardware Supply Chain Compromise Detection via Host Status & Boot Integrity Checks (`DET0368`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1195.003](https://attack.mitre.org/techniques/T1195/003/) · [detail page](../../techniques/initial-access.md#t1195003)

- **`AN1035` Analytic 1035** · Windows
  Detects tampered hardware or firmware via anomalous host status telemetry. Behavioral chain: (1) Pre-OS or firmware components exhibit unexpected version changes, signature failures, or modified boot paths; (2) System management/firmware tools log hardware inventory drift; (3) Sensor health telemetry or boot attestation events fail baseline checks; (4) Follow-on process execution from altered firmware or unknown drivers after boot.
  - *Log sources:* `WinEventLog:Security` (EventCode=1166, 7045); `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` (Code integrity violations in boot-start drivers or firmware); `WinEventLog:Sysmon` (EventCode=6); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `BaselineFirmwareVersion` — Expected firmware/BIOS version for each hardware model.; `BaselineDriverList` — Approved boot-start drivers.; `IntegrityCheckInterval` — Frequency of integrity checks (e.g., daily, weekly).
- **`AN1036` Analytic 1036** · Linux
  Monitors for hardware or firmware tampering by correlating system boot logs, hardware inventory changes, and secure boot/firmware verification failures. Behavioral chain: (1) UEFI/BIOS version drift; (2) secure boot disabled or signature verification errors; (3) unexpected modules or hardware devices enumerated at boot; (4) new device firmware images loaded from non-approved sources.
  - *Log sources:* `auditd:SYSCALL` (firmware_update, kexec_load); `fwupd:logs` (Firmware updates applied or failed)
  - *Tune:* `ApprovedFirmwareHashes` — List of SHA256/SHA512 firmware hashes allowed.; `AllowedDeviceIDs` — Known hardware component IDs per host baseline.
- **`AN1037` Analytic 1037** · macOS
  Detects tampered Mac hardware/firmware by analyzing unified logs, EndpointSecurity events, and Apple Mobile File Integrity (AMFI) checks. Behavioral chain: (1) Boot process reports firmware signature mismatch; (2) Secure Boot policy altered; (3) new EFI drivers or hardware devices appear in inventory; (4) system extension loads from unapproved developer IDs post-boot.
  - *Log sources:* `macos:unifiedlog` (EFI firmware integrity check failed); `macos:endpointsecurity` (es_event_authentication)
  - *Tune:* `AllowedTeamIDs` — Developer Team IDs approved for kext/system extension loads.; `FirmwareVersionBaseline` — Expected EFI/firmware version for Mac model.

---

### T1199 — Trusted Relationship
<a id="t1199"></a>

**Detection strategy:** Detect abuse of Trusted Relationships (third-party and delegated admin access) (`DET0488`)  
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1199](https://attack.mitre.org/techniques/T1199/) · [detail page](../../techniques/initial-access.md#t1199)

- **`AN1344` Analytic 1344** · Windows
  Behavioral chain: (1) a login from a third-party account or untrusted source network establishes an interactive/remote session; (2) the session acquires elevated privileges or accesses sensitive resources atypical for that account; (3) subsequent lateral movement or data access occurs from the same session/device. Correlate Windows logon events, token elevation/privileged use, and resource access with third-party context.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Security` (EventCode=4776, 4771, 4770); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `ThirdPartyCIDRs` — Ranges used by MSPs/contractors/VPN egress; used to enrich logons and network flows.; `ExpectedAdminHosts` — Servers where third-party admins are allowed; deviations raise risk.; `TimeWindow` — Correlation window linking logon → elevation → access (e.g., 30–120 minutes).; `HighValueResources` — File shares/AD objects/servers that should never be touched by third-party sessions.
- **`AN1345` Analytic 1345** · Linux
  Behavioral chain: (1) sshd or federated SSO logins from third-party networks or identities; (2) rapid sudo/su privilege elevation; (3) access to sensitive paths or east-west SSH. Correlate auth logs, process execution, and network flows.
  - *Log sources:* `auditd:SYSCALL` (execve,socket,connect,openat); `linux:syslog` (Accepted publickey/password for * from * port * ssh2); `NSM:Flow` (ssh connections originating from third-party CIDRs)
  - *Tune:* `ThirdPartyUsers` — POSIX accounts assigned to vendors/partners.; `AllowedJumpHosts` — Bastion hosts permitted for third-party access.; `MFAExpected` — Flag indicating whether PAM/MFA should be present; used to score risk.
- **`AN1346` Analytic 1346** · macOS
  Behavioral chain: (1) third-party interactive login or mobileconfig-based device enrollment; (2) privilege use or admin group change; (3) lateral movement mounts/ssh. Correlate unified logs and network telemetry.
  - *Log sources:* `macos:unifiedlog` (loginwindow or sshd successful login events); `macos:unifiedlog` (Group membership change for admin or wheel); `NSM:Flow` (ssh/smb connections to internal resources from third-party devices)
  - *Tune:* `ManagedDeviceList` — Known corp devices; treat unknown devices as higher risk.
- **`AN1347` Analytic 1347** · Identity Provider
  Behavioral chain: (1) delegated admin or external identity establishes session (e.g., partner/reseller DAP, B2B guest, SAML/OAuth trust); (2) role elevation or app consent/permission grant; (3) downstream privileged actions in the tenant. Correlate IdP sign-in, admin/role assignment, and consent/admin-on-behalf events.
  - *Log sources:* `azure:signinlogs` (InteractiveUser, ServicePrincipalSignIn); `azure:audit` (Add delegated admin / Assign admin roles / Update application consent); `m365:unified` (Set-PartnerOfRecord / CompanyAdministrator role assignments / New-DelegatedAdminRelationship)
  - *Tune:* `TrustedPartnerTenantIDs` — Tenant IDs of approved partners; any others are suspicious.; `RequiredMFA` — Require MFA for partner sessions; alert on bypass or step-up failure.; `RoleScopeAllowList` — Roles third-parties may hold (e.g., Helpdesk Admin); flag broader scopes.
- **`AN1348` Analytic 1348** · IaaS
  Behavioral chain: (1) cross-account or third-party principal assumes a role into the tenant/subscription/project; (2) privileged API calls are made in short succession; (3) access originates from unfamiliar networks or geos. Correlate assume-role/federation events with sensitive API usage.
  - *Log sources:* `AWS:CloudTrail` (AssumeRole,AssumeRoleWithSAML,AssumeRoleWithWebIdentity); `AWS:CloudTrail` (CreateUser|AttachRolePolicy|CreateAccessKey|UpdateAssumeRolePolicy|CreateLoginProfile); `gcp:audit` (google.iam.credentials.generateAccessToken / serviceAccountTokenCreator)
  - *Tune:* `ExternalAccountAllowList` — Cross-account principals permitted to assume roles; used for allow-listing.; `SensitiveAPIs` — Provider-specific list of risky APIs for scoring.; `GeoVelocityThreshold` — Detect impossible travel between partner and tenant actions.
- **`AN1349` Analytic 1349** · SaaS
  Behavioral chain: (1) third-party app or admin connects via OAuth/marketplace install; (2) high-privilege scopes granted; (3) anomalous actions (mass read/exports, admin changes).
  - *Log sources:* `saas:googleworkspace` (OAuth2 authorization grants / Admin role assignments); `saas:salesforce` (ConnectedApp OAuth policy change / Login as user)
  - *Tune:* `ApprovedApps` — Catalog of sanctioned third-party apps and scopes.; `ExportVolumeThreshold` — Data export size/rate baselines to detect abnormal partner activity.
- **`AN1350` Analytic 1350** · Office Suite
  Behavioral chain: (1) delegated administration offers/relationships created or modified by partner tenants; (2) mailbox delegation/impersonation enabled; (3) follow-on access from partner IPs.
  - *Log sources:* `m365:unified` (Add-DelegatedAdmin, Set-PartnerOfRecord, Add-MailboxPermission, Set-OrganizationRelationship); `azure:signinlogs` (InteractiveUser, NonInteractiveUser)
  - *Tune:* `MailboxDelegateAllowList` — Specific mailboxes third-parties may manage.

---

### T1200 — Hardware Additions
<a id="t1200"></a>

**Detection strategy:** Detect unauthorized or suspicious Hardware Additions (USB/Thunderbolt/Network) (`DET0069`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1200](https://attack.mitre.org/techniques/T1200/) · [detail page](../../techniques/initial-access.md#t1200)

- **`AN0185` Analytic 0185** · Windows
  Chain: (1) a new external device is recognized by Windows (USB/Thunderbolt/PCIe) or a new block device appears; (2) within a short window, the same user/session spawns processes or the OS mounts a new volume; (3) optional follow-on activity such as HID keystroke injection, DMA driver load, or new network interface MAC on DHCP. Correlate Security EID 6416 / Kernel-PnP with sysmon and DHCP/network metadata.
  - *Log sources:* `WinEventLog:Security` (EventCode=6416); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=6); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:System` (Kernel-PnP 410/400 device install, disk added); `wineventlog:dhcp` (DHCP Lease Granted)
  - *Tune:* `TrustedDeviceVIDPID` — Vendor/Product IDs that are approved (e.g., keyboards, mice). Unknown/rare VID:PID raise risk.; `ExpectedBusTypes` — Allow-listed bus types for server classes (e.g., USB disabled on DCs).; `TimeWindow` — Correlation window between device recognition and follow-on process/mount/network activity (e.g., 10m–60m).; `TrustedMACs` — Known NIC/USB-NIC MAC addresses allowed by policy.
- **`AN0186` Analytic 0186** · Linux
  Chain: (1) udev / kernel logs show hot-plug (USB/Thunderbolt/PCIe); (2) block device created by udisks/diskarbitration; (3) optional: new network interface or DHCP lease observed. Correlate /var/log/messages|syslog, auditd SYSCALL open/creat on /dev, and DHCP/Zeek.
  - *Log sources:* `auditd:SYSCALL` (mknod,open,openat); `linux:syslog` (usb * new|thunderbolt|pci .* added|block.*: new .* device); `NSM:Flow` (LEASE_GRANTED)
  - *Tune:* `BlocklistDeviceStrings` — Indicators such as 'RubberDucky', 'BadUSB', unfamiliar USB-NIC chipsets.; `ServerClassesNoUSB` — Hosts where any USB attach should alert (DCs, hypervisors).; `DHCPVlanScopes` — Scopes allowed to issue leases for corp endpoints vs. guest/IoT.
- **`AN0187` Analytic 0187** · macOS
  Chain: (1) unified logs report IOUSBHost/IOThunderbolt device arrival; (2) diskarbitrationd attaches a new volume; (3) optional: config profile manipulation or new network interface MAC obtains a lease. Correlate unifiedlogs (subsystems: IOUSBHost, IOKit, diskarbitrationd), FSEvents, and DHCP/Zeek.
  - *Log sources:* `macos:unifiedlog` (Device attached|enumerated VID/PID); `macos:unifiedlog` (mounted|appeared|DA: disk* attached); `NSM:Flow` (MAC not in allow-list acquiring IP (DHCP))
  - *Tune:* `ManagedUSBPolicy` — MDM profile expectations for external media and Thunderbolt mode; deviations alert.; `KnownAppleAccessories` — VID/PID for corporate-issued docks/keyboards.

---

### T1566 — Phishing
<a id="t1566"></a>

**Detection strategy:** Detection Strategy for Phishing across platforms. (`DET0070`)  
**Platforms:** Identity Provider, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1566](https://attack.mitre.org/techniques/T1566/) · [detail page](../../techniques/initial-access.md#t1566)

- **`AN0188` Analytic 0188** · Windows
  Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a phishing message is received.
  - *Log sources:* `m365:unified` (Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `SuspiciousFileTypes` — Attachment types considered high risk (e.g., .exe, .js, .vbs, .scr, macro-enabled docs).; `AllowedSenders` — Whitelist of known trusted senders to reduce false positives.
- **`AN0189` Analytic 0189** · Linux
  Monitor for malicious payload delivery through phishing where attachments or URLs in email clients (e.g., Thunderbird, mutt) result in unusual file creation or outbound network connections. Focus on correlation between mail logs, file writes, and execution activity.
  - *Log sources:* `Application:Mail` (Inbound messages with anomalous headers, spoofed SPF/DKIM failures); `auditd:SYSCALL` (execve: Execution of scripts or binaries sourced from mail directories (/var/mail, ~/Maildir))
  - *Tune:* `MonitoredMailPaths` — System or user directories where emails/attachments are stored.; `AttachmentHashBaseline` — Known good hashes for common business document templates.
- **`AN0190` Analytic 0190** · macOS
  Detection of phishing through anomalous Mail app activity, such as attachments saved to disk and immediately executed, or Safari/Preview launching URLs and files linked from email messages. Correlate UnifiedLogs events with subsequent process execution.
  - *Log sources:* `macos:unifiedlog` (Inbound email activity with suspicious domains or mismatched sender information); `macos:unifiedlog` (Preview.app, Safari.app, or Mail.app spawning new processes outside normal patterns)
  - *Tune:* `SuspiciousDomains` — List of domains known for phishing activity or suspicious sender infrastructure.; `ExecutionDelayWindow` — Time threshold between file save and execution considered suspicious.
- **`AN0191` Analytic 0191** · Office Suite
  Phishing via Office documents containing embedded macros or links that spawn processes. Detection relies on correlating Office application logs with suspicious child process execution and outbound network connections.
  - *Log sources:* `m365:unified` (FileAccessed: Access of email attachments by Office applications); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `ParentProcessList` — Parent processes expected to execute child processes (e.g., Office apps).; `MacroExecutionThreshold` — Threshold for number of macros executed before raising alerts.
- **`AN0192` Analytic 0192** · Identity Provider
  Phishing attempts targeting IdPs often manifest as anomalous login attempts from suspicious email invitations or fake SSO prompts. Detection correlates login flows, MFA bypass attempts, and anomalous geographic patterns following phishing email delivery.
  - *Log sources:* `azure:signinlogs` (Failed MFA attempts, unusual conditional access triggers, login attempts from unexpected IP ranges)
  - *Tune:* `GeoAnomalyThreshold` — Allowed distance/time delta between user sign-ins.; `MFABypassIndicators` — Signals of repeated or anomalous MFA failures linked to phishing campaigns.
- **`AN0193` Analytic 0193** · SaaS
  Phishing delivered via SaaS services (chat, collaboration platforms) where messages contain malicious URLs or attachments. Detect anomalous link clicks, suspicious file uploads, or token misuse after SaaS-based phishing attempts.
  - *Log sources:* `saas:collaboration` (MessagePosted: Suspicious links or attachment delivery via collaboration tools (Slack, Teams, Zoom))
  - *Tune:* `MonitoredSaaSApps` — Scope of SaaS platforms under phishing monitoring.; `LinkInspectionPolicy` — Threshold for auto-expansion and detonation of URLs sent in SaaS messages.

---

### T1566.001 — Spearphishing Attachment
<a id="t1566001"></a>

**Detection strategy:** Detection Strategy for Spearphishing Attachment across OS Platforms (`DET0236`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1566.001](https://attack.mitre.org/techniques/T1566/001/) · [detail page](../../techniques/initial-access.md#t1566001)

- **`AN0655` Analytic 0655** · Windows
  Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk → process execution → outbound network activity.
  - *Log sources:* `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `AttachmentExtensions` — List of high-risk extensions to monitor (e.g., .exe, .js, .vbs, .docm, .xlsm).; `SuspiciousParentChildPairs` — Process lineage patterns considered malicious (e.g., winword.exe → powershell.exe).; `TimeWindow` — Correlation window between email receipt, file creation, and process execution.
- **`AN0656` Analytic 0656** · Linux
  Phishing attachments executed on Linux systems are detected by linking email logs to file creation in mail directories and subsequent suspicious process execution. Look for unexpected binaries or scripts spawned from user mail directories and anomalous outbound network activity.
  - *Log sources:* `Application:Mail` (Inbound email attachments logged from MTAs with suspicious metadata); `auditd:SYSCALL` (execve: Execution of files saved in mail or download directories); `NSM:Flow` (Outbound traffic from suspicious new processes post-attachment execution)
  - *Tune:* `AttachmentStoragePaths` — Monitored directories for email attachments (e.g., /var/mail, ~/Maildir, ~/Downloads).; `ScriptInterpreters` — List of interpreters to monitor when spawned by mail clients (e.g., bash, python, perl).
- **`AN0657` Analytic 0657** · macOS
  Phishing attachment detection on macOS through correlation of Mail app logs, file creation in user directories, and abnormal process execution (e.g., Preview.app or Mail.app spawning Terminal or scripting binaries). Network traffic after attachment interaction is also monitored.
  - *Log sources:* `macos:unifiedlog` (Inbound messages with attachments from suspicious domains); `macos:unifiedlog` (Execution of Terminal, osascript, or other interpreters originating from Mail or Preview); `macos:unifiedlog` (Attachment files written to ~/Downloads or temporary folders)
  - *Tune:* `ExecutionDelayThreshold` — Time delay between attachment download and execution considered suspicious.; `SuspiciousParentApps` — Parent processes expected to rarely spawn child processes (e.g., Mail.app, Preview.app).

---

### T1566.002 — Spearphishing Link
<a id="t1566002"></a>

**Detection strategy:** Detection Strategy for Spearphishing Links (`DET0107`)  
**Platforms:** Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1566.002](https://attack.mitre.org/techniques/T1566/002/) · [detail page](../../techniques/initial-access.md#t1566002)

- **`AN0298` Analytic 0298** · Windows
  Correlation of inbound emails with embedded links followed by user-driven browser navigation to suspicious or obfuscated domains. Detection chain includes malicious URL in email → user click recorded in Office logs → browser process spawning unusual child processes (e.g., PowerShell, cmd) or download activity.
  - *Log sources:* `m365:unified` (Send/Receive: Inbound emails containing embedded or shortened URLs); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `SuspiciousTLDs` — List of monitored top-level domains commonly abused in phishing (e.g., .xyz, .top, .tk).; `URLShortenerDomains` — Domains like bit.ly, tinyurl.com flagged for deeper expansion/inspection.; `ClickToExecutionWindow` — Time threshold between URL click and suspicious process execution.
- **`AN0299` Analytic 0299** · Linux
  Detection of spearphishing links through mail logs and browser activity. Behavior includes email with suspicious URLs → user click recorded in mail/web proxy logs → shell or interpreter launched from browser process.
  - *Log sources:* `Application:Mail` (Inbound emails containing hyperlinks from suspicious sources); `auditd:SYSCALL` (execve: Execution of scripts or binaries spawned from browser processes); `NSM:Flow` (Outbound requests to domains not previously resolved or associated with phishing campaigns)
  - *Tune:* `MonitoredBrowsers` — List of browser processes to monitor (e.g., firefox, chrome, chromium).; `PhishingIndicators` — Custom regex patterns for detecting obfuscated or IDN homograph URLs.
- **`AN0300` Analytic 0300** · macOS
  Correlation of Mail.app logs with Safari/Chrome activity. Suspicious behavior includes email links → Safari/Chrome accessing newly registered or lookalike domains → osascript or Terminal spawned unexpectedly.
  - *Log sources:* `macos:unifiedlog` (Received messages with embedded or shortened URLs); `macos:unifiedlog` (Browser processes launching unexpected interpreters (osascript, bash)); `macos:unifiedlog` (Connections to suspicious domains with mismatched certificate or unusual patterns)
  - *Tune:* `CertificateAnomalies` — Flag self-signed or mismatched TLS certificates from spearphishing domains.; `ExecutionDelayThreshold` — Suspicious delay between URL click and malicious process spawn.
- **`AN0301` Analytic 0301** · Identity Provider
  Detection of OAuth consent phishing or malicious login attempts initiated through spearphishing links. Behavior chain includes inbound email with OAuth URL → consent page visited → unusual token grants logged in IdP logs.
  - *Log sources:* `azure:signinlogs` (ConsentGrant: Suspicious consent grants to non-approved or unknown applications)
  - *Tune:* `AllowedApps` — Whitelisted apps permitted for OAuth consent grants.; `AnomalousConsentPatterns` — Patterns of consent from unusual geographies, devices, or unapproved applications.

---

### T1566.003 — Spearphishing via Service
<a id="t1566003"></a>

**Detection strategy:** Detection Strategy for Spearphishing via a Service across OS Platforms (`DET0115`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1566.003](https://attack.mitre.org/techniques/T1566/003/) · [detail page](../../techniques/initial-access.md#t1566003)

- **`AN0320` Analytic 0320** · Windows
  Inbound spearphishing attempts delivered via third-party services (e.g., Gmail, LinkedIn messages) leading to malicious file downloads or browser-initiated script execution. Defender view includes correlation of external service logins, unexpected file write operations, and suspicious descendant processes spawned from productivity or browser applications.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `MonitoredServices` — List of third-party services (e.g., Gmail, LinkedIn, Dropbox) relevant to the organization’s threat profile.; `SuspiciousProcessPatterns` — Process lineage and parent-child execution relationships considered abnormal (e.g., outlook.exe → powershell.exe).; `TimeWindow` — Correlates file creation and outbound connection activity within a tunable time period after message receipt.
- **`AN0321` Analytic 0321** · Linux
  Use of non-enterprise email or messaging services in Thunderbird, Evolution, or browsers leading to suspicious file downloads and subsequent execution. Defender view includes browser-initiated downloads of unexpected content and shell or interpreter processes launched post-download.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of bash, python, or perl processes spawned by browser/email client); `linux:syslog` (Inbound messages from webmail services containing attachments or URLs); `NSM:Flow` (Outbound traffic to domains/IPs not previously resolved, occurring shortly after attachment download or link click)
  - *Tune:* `BrowserProcesses` — Configured list of browsers or email clients to monitor (e.g., firefox, chromium, thunderbird).; `PhishingIndicators` — Custom regex rules for suspicious URL patterns, file extensions, or encoded links.
- **`AN0322` Analytic 0322** · macOS
  Phishing attempts via iCloud Mail, Gmail, or social media apps accessed on macOS systems. Defender view includes Mail.app or Safari downloads of files followed by osascript, Terminal, or abnormal child process execution.
  - *Log sources:* `macos:unifiedlog` (Received messages containing embedded links or attachments from non-enterprise services); `macos:unifiedlog` (Execution of osascript, bash, or Terminal initiated from Mail.app or Safari); `macos:unifiedlog` (Suspicious outbound HTTPS requests to domains flagged as newly registered or untrusted after spearphishing message interaction)
  - *Tune:* `CertificateChecks` — Flagging mismatched or self-signed certificates during outbound connections initiated after spearphishing messages.; `ExecutionDelay` — Window of time between attachment download and subsequent suspicious execution.

---

### T1566.004 — Spearphishing Voice
<a id="t1566004"></a>

**Detection strategy:** Detection Strategy for Spearphishing Voice across OS platforms (`DET0245`)  
**Platforms:** Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1566.004](https://attack.mitre.org/techniques/T1566/004/) · [detail page](../../techniques/initial-access.md#t1566004)

- **`AN0683` Analytic 0683** · Windows
  Monitor call log records from corporate devices for unusual or unauthorized numbers, especially repeated calls to/from known malicious phone numbers. Correlate with subsequent system events (e.g., browser navigation, remote management tool execution).
  - *Log sources:* `ApplicationLog:CallRecords` (Outbound or inbound calls to high-risk or blocklisted numbers)
  - *Tune:* `PhoneNumberBlocklist` — List of known malicious or suspicious phone numbers; must be tuned per environment; `TimeWindow` — Threshold for correlating call events with subsequent suspicious system activity
- **`AN0684` Analytic 0684** · Linux
  Audit VoIP/SIP logs for suspicious outbound calls or call setup messages to unusual endpoints. Correlate with user activity such as browser execution or package installation following the call.
  - *Log sources:* `networkdevice:syslog` (SIP REGISTER, INVITE, or unusual call destination metadata)
  - *Tune:* `CallDestinationPatterns` — Regular expressions or rules for spotting abnormal call destinations; `UserContext` — Expected users who initiate VoIP traffic vs. anomalous accounts
- **`AN0685` Analytic 0685** · macOS
  Monitor Facetime, iMessage, or SIP client logs for anomalous voice call attempts. Link to subsequent user execution events (downloads, RMM installs) triggered post-call.
  - *Log sources:* `macos:unifiedlog` (Outgoing or incoming calls with non-standard caller IDs or unusual metadata)
  - *Tune:* `CallerIDPatterns` — Patterns of spoofed caller IDs that must be tuned based on region and telecom provider; `PayloadCorrelation` — Define what follow-on events (browser downloads, execution) to correlate with call logs
- **`AN0686` Analytic 0686** · Identity Provider
  Correlate MFA push fatigue or unusual consent grant attempts with call activity where adversaries may have socially engineered the user over voice.
  - *Log sources:* `m365:unified` (Unusual MFA requests or OAuth consent events temporally aligned with user-reported vishing call)
  - *Tune:* `MFARequestThreshold` — Number of MFA push requests within a timeframe aligned to a suspicious call; `ConsentGrantPatterns` — Unusual OAuth consent URLs or delegated scopes

---

### T1659 — Content Injection
<a id="t1659"></a>

**Detection strategy:** Detection Strategy for Content Injection (`DET0349`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1659](https://attack.mitre.org/techniques/T1659/) · [detail page](../../techniques/initial-access.md#t1659)

- **`AN0992` Analytic 0992** · Windows
  Detect suspicious file creations and process executions triggered by browser activity (e.g., injected payloads written to %AppData% or Temp directories, then executed). Correlate network anomalies with subsequent local process creation or script execution.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `NSM:Flow` (Unexpected script or binary content returned in HTTP response body)
  - *Tune:* `MonitoredExtensions` — File extensions to flag (exe, dll, js, vbs, sh, etc.).; `SuspiciousParentProcesses` — Browser processes (chrome.exe, firefox.exe, edge.exe, etc.) monitored as possible parents for malicious activity.; `RedirectList` — List of suspicious domains or URLs used for malicious redirects.
- **`AN0993` Analytic 0993** · Linux
  Detect curl/wget commands saving executable/script payloads to /tmp or /var/tmp followed by execution. Monitor packet captures or IDS/IPS alerts for injected responses or mismatched content types.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of curl or wget writing files to /tmp/* followed by chmod or execution); `WinEventLog:Sysmon` (File creation of suspicious scripts/binaries in temporary directories); `NSM:Flow` (Injected content responses with unexpected script/malware signatures)
  - *Tune:* `TempDirectories` — Directories such as /tmp and /var/tmp where injected files are often written.
- **`AN0994` Analytic 0994** · macOS
  Monitor unified logs for processes spawned from Safari or other browsers that immediately load scripts or executables. Detect file drops in ~/Library/Caches or ~/Downloads that execute shortly after being written.
  - *Log sources:* `macos:unifiedlog` (Child processes of Safari, Chrome, or Firefox executing scripting interpreters); `macos:unifiedlog` (File creation of unsigned binaries/scripts in user cache or download directories); `NSM:Flow` (Content injection observed in HTTPS responses with mismatched certificates or altered payloads)
  - *Tune:* `MonitoredDirectories` — macOS-specific directories where malicious payloads may be written.

---

### T1669 — Wi-Fi Networks
<a id="t1669"></a>

**Detection strategy:** Detection Strategy for Wi-Fi Networks (`DET0536`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1669](https://attack.mitre.org/techniques/T1669/) · [detail page](../../techniques/initial-access.md#t1669)

- **`AN1476` Analytic 1476** · Windows
  Detects anomalous wireless connections such as unexpected SSID associations, failed or repeated authentication attempts, and connections outside of known geofenced networks. Defenders should monitor wireless connection logs and event codes for network discovery, authentication, and association events.
  - *Log sources:* `WinEventLog:Microsoft-Windows-WLAN-AutoConfig` (EventCode=8001, 8002, 8003); `WinEventLog:Security` (EventCode=4776, 4625)
  - *Tune:* `KnownSSIDList` — Defines approved Wi-Fi SSIDs for the environment; deviations may indicate malicious connection attempts.; `GeoLocationContext` — Correlates expected physical location of systems with observed Wi-Fi connections to detect anomalies.
- **`AN1477` Analytic 1477** · Linux
  Detects unauthorized wireless associations by monitoring wpa_supplicant logs, NetworkManager events, and system calls related to interface state changes. Anomalies include repeated association failures, new SSIDs outside baselined values, and rogue AP connections.
  - *Log sources:* `linux:syslog` (New Wi-Fi connection established or repeated association failures); `auditd:SYSCALL` (ioctl: Changes to wireless network interfaces (up, down, reassociate))
  - *Tune:* `AllowedSSIDRegex` — Regex-based whitelist of corporate SSIDs; anomalous matches indicate suspicious activity.; `RetryThreshold` — Number of failed association attempts allowed before triggering detection.
- **`AN1478` Analytic 1478** · macOS
  Detects unauthorized Wi-Fi associations and SSID scanning activity using unified logs and airport command telemetry. Anomalies include rapid SSID switching, connections to unapproved SSIDs, or repeated authentication failures.
  - *Log sources:* `macos:unifiedlog` (Association and authentication events including failures and new SSIDs); `macos:osquery` (query: Historical list of associated SSIDs compared against baseline)
  - *Tune:* `BaselineSSIDHistory` — Historical record of corporate SSID associations per device; deviations may indicate rogue AP usage.
- **`AN1479` Analytic 1479** · Network Devices
  Detects rogue or suspicious wireless access attempts by monitoring firewall, WIDS/WIPS, and controller logs. Focus is on firewall rule changes, rogue AP detection, and anomalous MAC addresses connecting to access points.
  - *Log sources:* `NSM:Firewall` (rule_modification: New or modified firewall rules related to wireless interfaces); `WIDS:AssociationLogs` (Unauthorized AP or anomalous MAC address connection attempts)
  - *Tune:* `AuthorizedAPList` — Defines known access points and MAC addresses; deviations highlight rogue or unauthorized devices.

---

