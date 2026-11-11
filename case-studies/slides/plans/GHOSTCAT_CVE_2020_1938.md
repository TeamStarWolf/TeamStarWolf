# Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab

- Study: case-studies/GHOSTCAT_CVE_2020_1938.md
- Cover title: Ghostcat, CVE-2020-1938 / The Tomcat AJP File Read / in the Lab
- Subtitle: A default-on second port, a file that HTTP refused, and a fix that held in the lab
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/GHOSTCAT_CVE_2020_1938.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A default-on second port let anyone read Tomcat's private files

- Until February 2020 a stock Tomcat opened an AJP/1.3 connector on port 8009 on every address, and Tomcat trusts AJP more than HTTP.
- Anyone who could reach port 8009 could make Tomcat return any web-application file, including WEB-INF and META-INF, or process one as a JSP.
- The fix shipped first: 9.0.31 and 8.5.51 on 11 February 2020 and 7.0.100 on 14 February, before the 20 February public notices.
- CISA added CVE-2020-1938 to KEV on 3 March 2022, and it was still listed on 3 November 2026.
- In the lab, 9.0.30 served WEB-INF/web.xml over AJP while HTTP returned 404; a 9.0.31 control with AJP reopened answered 403.
Caption: Evidence grade: Confirmed for the flaw, the fix and the KEV listing; Demonstrated for the lab results.
Notes: Default connector and AJP trust [1][2][3]. Report to Apache on 3 January 2020 and the two capabilities [1][18]. Fix releases [1][3][4][5][6]. CNVD and Chaitin notices of 20 February 2020 [18][19]. KEV listing and the 3 November 2026 catalog [23]. Lab read, 404 and 403 [67][69].

## KEY FACTS | Every common risk signal points at Ghostcat today

Stat: 9.8 | CVSS 3.1 base score from NVD and CISA-ADP
Stat: 0.9927 | EPSS score on 3 November 2026
Stat: 2022 | CISA added it to KEV on 3 March
Stat: 8009 | The AJP port, open on all addresses by default
- Affected: 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99; Chaitin and CNVD also list all of 6.x.
- Fixed: 9.0.31 and 8.5.51 on 11 February 2020, and 7.0.100 on 14 February 2020.
- CISA SSVC: exploitation active, automatable, technical impact total (6 February 2025).
Notes: CVSS 3.1 9.8 [21][22]. EPSS 0.9927, percentile 0.99937 [25]. KEV added 3 March 2022, due 17 March 2022 [23]. Default connector on all addresses [1]. Affected and fixed versions [1][2][3][15][18][19]. SSVC [22].

## PART 1 | AJP was built to trust a proxy, and nothing kept others out

- AJP/1.3 is a binary protocol a front-end web server uses to forward requests to Tomcat, with facts the proxy has established, such as the client address or the user.
- Because those facts should come from the proxy, Tomcat treats an AJP connection as more trusted than an HTTP one.
- The stock connector listened on every configured address; Tomcat's security guide expected administrators to disable it if they did not need it.
- Risks known before Ghostcat: bypassing client-IP checks, and bypassing authentication where Tomcat trusted proxy-supplied data.
Caption: The trust was safe only if nobody else could reach the connector, and the default did not ensure that.
Notes: AJP's role and trust level [1][3][16]. Default-on connector and the security guide [1][2]. Risks known before Ghostcat [3].

## PART 1 | Unchecked request attributes turned that trust into a file read

Left: What Ghostcat added
- Return any file in a web application, including the private WEB-INF and META-INF folders.
- Process any web-application file as a JSP; with a file the attacker controls, such as an upload, that is code execution.
Right: How it worked
- Before commit 64fa5b99 of 21 January 2020, the AJP processor set any unrecognised request attribute without checking it.
- The public probe names the file through three javax.servlet.include attributes.
- Apache's advisory does not name the attributes; the probe's source and the fix commit do.
Caption: By default the flaw is a file read; code execution needs an attacker-controlled file inside the application.
Notes: The two capabilities [1][18]. The unchecked attributes in AjpProcessor.prepareRequest before 64fa5b99 [12]. The three include attributes in the pinned probe [58][66]. Code execution conditional on an attacker-controlled file [1][18][36].

## PART 1 | The February 2020 fix closed the connector four ways

| Change | Effect |
|---|---|
| Off by default | The AJP/1.3 connector is commented out in server.xml |
| Loopback bind | The default bind address becomes the loopback address |
| Secret required | requiredSecret becomes secret, and secretRequired defaults to true, so the connector will not start without one |
| Attribute allow-list | Requests with unrecognised attributes are refused with a 403 unless allowedRequestAttributesPattern allows them |
Caption: Apache warns that upgrading will likely need small configuration changes, because the defaults were hardened.
Notes: The 9.0.31, 8.5.51 and 7.0.100 changelogs [4][5][6]. The current connector reference [7]. Apache's warning about configuration changes [1].

## PART 1 | The quiet fix shipped nine days before the first public notice

| Date | Event |
|---|---|
| 3 January 2020 | Chaitin Tech reports the flaw to the Apache Tomcat Security Team |
| 11 February 2020 | Tomcat 9.0.31 and 8.5.51 released |
| 14 February 2020 | Tomcat 7.0.100 released |
| 20 February 2020 | CNVD and Chaitin notices; Exploit-DB EDB-48143 published |
| 24 February 2020 | Apache makes the issue public; NVD publishes CVE-2020-1938 |
| 29 Feb to 1 Mar 2020 | Bad Packets reports mass scanning for /WEB-INF/web.xml |
| 3 March 2022 | CISA adds CVE-2020-1938 to the KEV catalog |
Notes: Report [1][18]. Releases [1][2][3][4][5][6]. Notices and the first public proof of concept [18][19][20][38]. Apache and NVD publication [1][21]. Scanning, as relayed [43][44][45]. KEV [23][24]. Nine days is the study's arithmetic from 11 to 20 February.

## PART 2 | Scanning arrived within days, but no actor has been named

Stat: 85,318 | DShield port 8009 events on 21 February 2020, against 1,000 to 7,000 a day
Stat: 312 | Ghostcat payloads in a June 2026 honeypot report, from 65 source IPs
Stat: 61 | CIRCL sightings of the CVE as of 4 November 2026
- Exploit-DB EDB-48143 appeared on 20 February 2020, and a Metasploit module followed in November 2020.
- KEV lists the CVE and SSVC says exploitation is active, but no opened source names an actor, campaign or malware family.
- Recorded Future's September 2026 landscape lists it as exploited or weaponized that month (Reported, single source).
Notes: DShield counts port traffic, not Ghostcat requests, so the link to Ghostcat is Inferred [46]. Honeypot report, Reported [52]. CIRCL sightings [54]. Exploit-DB and Metasploit [38][39]. KEV, SSVC and the absence of a named actor [22][23][48]. Recorded Future [49].

## PART 2 | Exposure counts measure fingerprints, not vulnerable hosts

| Count | What it measures | Grade |
|---|---|---|
| 43,197 of about 555,000 | Affected Tomcat AJP IPs in China, CNVD's own count, February 2020 | Confirmed |
| 773 | Vulnerable Dutch IP addresses, DIVD CSIRT, 22 February 2020 | Reported |
| More than 170,000 | Devices exposing an AJP connector (ONYPHE), late February 2020 | Reported |
| About 1 million | Shodan and BinaryEdge, relayed by AppCheck | Reported |
| 1,240,557 | ajp13 fingerprints in a ZoomEye query of 25 October 2026 | Reported |
Caption: No count in the record says how many hosts were both reachable and unpatched.
Notes: CNVD [19]. DIVD [37]. ONYPHE, relayed [40][41][45]. Shodan and BinaryEdge [40]. ZoomEye, relayed with the caution that the fingerprint carries no version [53].

## PART 3 | On 9.0.30, AJP handed over a file that HTTP refused

Left: Vulnerable build, Tomcat 9.0.30
- version.sh printed Server number 9.0.30.0.
- Port 8009 listened on all addresses inside the container.
- The nuclei template matched, and poc.py returned WEB-INF/web.xml.
- HTTP for /WEB-INF/web.xml returned 404.
Right: Fixed control, Tomcat 9.0.31
- One added line reopened AJP on 0.0.0.0:8009 with secretRequired="false".
- Both probes got an HTTP Status 403 page.
- The licence sentence appeared once in the vulnerable output and not at all in the fixed one.
Caption: Lab of 3 November 2026: loopback-only Docker targets, pinned images and probes, the file-read half only.
Notes: Setup and pinned probes [65][66]. Vulnerable build results [67][68]. Control configuration and 403 results [67][69]. Pinning the 403 to the attribute check is Inferred, because the control had secretRequired="false" [4][69].

## PART 3 | The access log records the decoy request, not the file taken

- The lab plan expected AJP requests to leave no trace. On the 9.0.31 control, localhost_access_log recorded both probe requests with status 403.
- The logged lines are the forward URIs the probe chose as decoys, GET /examples/xxxxx.jsp and GET /asdf, never WEB-INF/web.xml.
- The stock AccessLogValve logs %r, the first line of the request, so the include path never appears.
- On AJP lines %h may be client-supplied, because a forward request carries its own remote_addr field.
Caption: The vulnerable build's access log was not checked; the same lines with status 200 are expected there (Inferred).
Notes: Log lines at 04/Nov/2026:04:10:18 +0000 [69]. The AccessLogValve pattern in 9.0.30 and 9.0.31 [11][14]. remote_addr in the probe [58]. The expectation for the vulnerable build is Inferred [14].

## DEFENDER VIEW | Find every Tomcat, then ask who can reach port 8009

| Check | What to run or read | Why |
|---|---|---|
| Version | bin/version.sh or version.bat, not the HTTP banner | The banner can be edited or hidden |
| Connector | grep -n -A4 'AJP/1.3' in each conf/server.xml | Each CATALINA_BASE has its own configuration |
| Reachability | ss -ltnp on the host and inside containers; nmap -sV -p 8009 | A loopback publish can hide an all-address bind |
| Packages | The distribution advisory's fixed package | Backported fixes report versions below the fix line |
| Embedded | tomcat-embed-core below 9.0.31, 8.5.51 or 7.0.100 | Embedded and bundled copies do not show as a service |
Caption: Scan only hosts you are authorized to test, from outside the network and from ordinary internal segments.
Notes: version.sh and the banner [8][68]. CATALINA_BASE [10]. Container and host binds [68]. Distribution packages [27][28]. Embedded jar [26]. Vendor bundles [30][31]. Lateral movement as the realistic abuse [36].

## DEFENDER VIEW | Upgrade is the fix; the connector changes are only bridges

Left: Apply the fix
- Move to a supported Tomcat at or above 9.0.31; 7.0 and 8.5 are end of life.
- On a distribution, install the vendor's fixed package; raise tomcat-embed-core in applications.
- Set the same secret on the connector and on mod_proxy_ajp or mod_jk.
Right: If you cannot upgrade yet
- Remove the connector if nothing uses AJP.
- Bind it to loopback or a private address with requiredSecret set.
- Firewall port 8009 so only the proxy can reach it.
- Upstream Tomcat 6 has no fix.
Caption: If port 8009 was reachable by untrusted sources, rotate the secrets kept in WEB-INF and META-INF.
Notes: Upgrade and end of life [1][2][7][15]. Distribution and embedded fixes [26][27][28]. Proxy secrets [16][17]. Bridges [8][17][18][29]. Tomcat 6 [15][27]. Secret rotation is the study's advice, Inferred [1][65].

## MITRE MAPPINGS | Two techniques shown in the lab, four more from the record

| Id | Technique | Tie to CVE-2020-1938 |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated access to AJP; Demonstrated in the lab |
| T1005 | Data from Local System | The read of WEB-INF/web.xml; Demonstrated in the lab |
| T1595.002 | Active Scanning: Vulnerability Scanning | The 2020 mass scanning (Reported) |
| T1046 | Network Service Discovery | The ajp13 fingerprint, seen from the defender's side |
| T1552.001 | Unsecured Credentials: Credentials In Files | Follow-on read of configuration files |
| T1505.003 | Server Software Component: Web Shell | Follow-on JSP code-execution path, not run in the lab |
Caption: The study's own mappings to ATT&CK v20.0; no published mapping exists for this CVE. MITRE notice in the notes.
Notes: Mappings and the absence of a CTID KEV mapping [61][62]. Rows [1][18][22][36][43][45][46][47][57][65][67][68]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Configuration decided the severity; the logs missed the intent

- **Defaults must enforce the trust they assume.** 9.0.31 turned AJP off, bound it to loopback, required a secret, and added a code check that held when the lab undid all three.
- **The quiet fix came first.** Teams that upgraded on Tomcat's release cadence were fixed before anyone knew to look.
- **Configuration decides the severity.** The same code is a 9.8 on a stock tarball and Low on a distribution that never opened AJP.
- **Logs record the request, not the intent.** Network signatures and source checks on port 8009 carry the detection weight.
- **No named actor does not mean no use.** KEV, SSVC, EPSS and 2026 reports keep pointing at Ghostcat.
Notes: Fix design and the lab control [4][7][67]. Release timing [1][19][38]. Ratings [21][29]. Log finding [69], probe [58], signatures [55]. Signals [22][23][25][47]; reports [49][52].
