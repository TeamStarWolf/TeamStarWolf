# Investigate a Phishing Report

> **By the end of this guide you will have taken a user-reported email from "this looks weird" to a documented verdict, purged it from every mailbox that received it, blocked the sender infrastructure, and told the reporter what happened.** Written for SOC analysts and IT generalists who handle "is this phishing?" tickets — no malware-analysis background required.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 30–90 minutes per report | Intermediate | The reported email in original form, Microsoft Defender portal access (or your mail gateway's console), a browser you never use to open suspect links directly | A written verdict with evidence, purge/block actions taken, defanged IOC list, and a reply to the reporter |

This guide uses Microsoft 365 with Defender for Office 365 for the console steps because that is the stack the library's email reference documents most deeply. Every phase — capture, headers, URL/attachment triage, scoping, purge/block/reset, closing the loop — applies identically on Google Workspace, Proofpoint, or Mimecast; swap in your gateway's equivalent console.

## Before you start

- [ ] Read the header-analysis and phishing-indicator sections of the library's [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md) — this guide operationalizes them and assumes their vocabulary (SPF/DKIM/DMARC, alignment, defanging).
- [ ] Confirm your Defender portal access: viewing needs a Security Reader-level role; purging email in Step 7 needs the **Search and Purge** role (or, in tenants on Microsoft Defender unified RBAC — the default for new Defender for Office 365 Plan 2 organizations starting July 2026 — the equivalent **Security operations/Security data/Email & collaboration advanced actions (manage)** permission) — see [Microsoft Defender for Office 365 permissions](https://learn.microsoft.com/en-us/defender-office-365/mdo-portal-permissions). Check this *before* an incident, not during one.
- [ ] Install the [Exchange Online PowerShell module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2) if you scope by message trace instead of (or in addition to) the portal.
- [ ] Bookmark [urlscan.io](https://urlscan.io/) and [VirusTotal](https://www.virustotal.com/) for URL and hash lookups that never touch your own machine.
- [ ] Know your escalation path: if the investigation confirms compromise, you hand off to the [phishing playbook in IR_PLAYBOOKS.md](/IR_PLAYBOOKS.md#phishing) — decide now who owns that.

## Step 1 — Capture the original message intact

Get the email as a file with full headers, not a screenshot and not an inline forward (forwarding rewrites headers and destroys the evidence you need in Step 2).

1. Best case: your users report through a **Report phishing** button, so the original lands on the **User reported** tab of the Submissions page (Defender portal → **Actions & submissions** → **Submissions**, or directly at `https://security.microsoft.com/reportsubmission`). Open it there.
2. If the report arrived as a plain email, ask the reporter to send the message **as an attachment** (drag the message into a new email, or use their client's forward-as-attachment option) so you receive a `.eml`/`.msg` file.
3. If you only need the headers fast, have the reporter copy them out:
   - **Classic Outlook (Windows):** open the message → **File** → **Properties** → copy the **Internet headers** box.
   - **New Outlook / Outlook on the web:** open the message → **More actions** (…) → **View** → **View message details**.
4. Save the file to your analysis location and hash it so your notes reference an exact artifact:

   ```powershell
   Get-FileHash -Algorithm SHA256 .\reported-message.eml
   ```

**Checkpoint:** You have a `.eml`/`.msg` file (or a full header block) plus its SHA-256, and a ticket/notes page where every finding from here on gets written down.

**Watch out:** Do not open attachments or click links while capturing. Saving the file is safe; rendering its content is not. If the reporter already clicked something, note that now — it changes Step 7 from "purge and block" to "purge, block, and reset."

## Step 2 — Read the headers and authentication results

Work through the headers exactly as the [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md) lays out. Paste the header block into a parser — [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) — or parse locally with [emlAnalyzer](https://pypi.org/project/eml-analyzer/):

```bash
pip install eml-analyzer
emlAnalyzer -i reported-message.eml --header --url --attachments
```

Answer four questions, in order:

1. **Did authentication pass?** Find the `Authentication-Results:` header and record the SPF, DKIM, and DMARC verdicts. `dmarc=fail` on a domain that claims to be your bank, your vendor, or your own org is a strong phish signal.
2. **Who really sent it?** Compare `From:` (what the user saw), `Return-Path:` (where bounces go), and `Reply-To:` (where replies go). Mismatches are classic phish plumbing.
3. **Where did it come from?** Read the `Received:` chain bottom-to-top — the bottom entry is the originating server. Check that IP against the claimed sender's published SPF record (`Resolve-DnsName senderdomain.example -Type TXT` in PowerShell; `dig TXT senderdomain.example` on macOS/Linux).
4. **Does "pass" actually clear it?** All three checks can pass on a phish. Display-name spoofing, cousin domains (`d0main.com`), and homoglyphs authenticate fine because the attacker controls the sending domain — the DMARC-gaps section of the reference covers each case. Authentication tells you *which domain sent it*, not *whether that domain is honest*.

**Checkpoint:** Your notes state the SPF/DKIM/DMARC results, the true originating IP and domain, and whether the visible sender identity matches the authenticated one.

**Watch out:** SPF routinely fails on legitimate mail that went through a forwarder or mailing list (the reference's ARC section explains why). One failing mechanism is a data point, not a verdict.

## Step 3 — Triage the URLs without touching them

Extract every URL (the `emlAnalyzer --url` output from Step 2, or hover-and-copy — never click). Then, for each:

1. **Defang it immediately** in your notes and in anything you share: `https://evil.example/pay` becomes `hxxps://evil[.]example/pay`. The URL-deobfuscation section of the [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md) has the conventions and a refang helper.
2. **Unwrap rewriting first.** Safe Links, Proofpoint URL Defense, and similar gateways wrap the real URL inside their own — decode to the true destination before judging it.
3. **Let a scanner visit it for you.** Submit to [urlscan.io](https://urlscan.io/) and review the screenshot, redirect chain, and verdicts. Set visibility to **Unlisted** or **Private** — a **Public** scan of a targeted phish can leak the campaign (and any tokens embedded in the URL) to the world, and can tip off the attacker that you're looking.
4. **Check reputation:** the domain's [VirusTotal](https://www.virustotal.com/) page (community verdicts, passive DNS, related samples) and WHOIS age. A domain registered days ago that renders a Microsoft 365 login page is not ambiguous.

**Checkpoint:** Every URL in the message is listed defanged in your notes with a per-URL verdict: credential-harvesting page, malware download, redirector, or benign.

**Watch out:** Many phishing kits fingerprint visitors — sandbox IP ranges get a 404 or a redirect to the real brand's site. A clean scanner result on a young, unrelated domain is *weak* evidence of safety. Also check for QR codes in the body: quishing moves the URL into an image where extraction misses it (Threat Explorer's **URL Source** filter has a **QR code** value for exactly this).

## Step 4 — Triage attachments in a sandbox, never on your desk

If the message carries attachments:

1. **Record name, type, and hash** for each (the `Get-FileHash` command from Step 1, or the attachment listing from `emlAnalyzer`). High-risk types called out in the reference: `.html` (HTML smuggling), `.iso`/`.img`, macro-enabled Office (`.docm`/`.xlsm`), and archives — especially password-protected archives with the password in the email body, which exist solely to defeat gateway scanning.
2. **Search the hash before you upload anything.** A SHA-256 search on VirusTotal discloses nothing about you and often returns a full verdict because someone else already submitted the same lure.
3. **Detonate unknowns in a sandbox**, not on your workstation: [ANY.RUN](https://any.run/) (interactive), [Joe Sandbox](https://www.joesandbox.com/), or your own isolated VM. Watch for dropped files, spawned processes, and outbound connections.
4. **Check what your gateway already did.** With Defender for Office 365, Safe Attachments has often already detonated the file — the message's Email entity page in the portal shows the detection technology and verdict, saving you the work.

**Checkpoint:** Each attachment has a hash and a verdict in your notes, and nothing was ever opened outside a sandbox.

**Watch out:** Uploading is publishing. If the attachment might contain your organization's data (a weaponized copy of a real internal document, an invoice with account details), do not put it on a public sandbox — use hash search, a private submission tier, or an internal sandbox instead.

## Step 5 — Call the verdict

Weigh Steps 2–4 together and commit to one of:

- **Phishing / malware** — hostile authentication picture, malicious URL or attachment verdicts, credential-harvesting page. Continue to Step 6.
- **BEC-style fraud** — no payload at all, just an urgent payment/gift-card/payroll request from a spoofed or lookalike identity. Continue to Step 6, and treat any mailbox that *replied* as potentially compromised (the BEC section of the [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md) lists the follow-on signals, such as new inbox forwarding rules).
- **Spam / graymail** — unwanted but not hostile. Block if noisy, close the ticket, still answer the reporter.
- **Legitimate** — it happens constantly; marketing mail with sloppy authentication is the classic false alarm. Close kindly: the user did the right thing by asking.

Write the verdict as one sentence plus the three strongest pieces of evidence. If you cannot decide, escalate with your notes rather than guessing — a wrong "clean" verdict is the expensive kind, and the Submissions page (Step 7) can also send the message to Microsoft for a second opinion.

**Checkpoint:** Your notes contain an explicit verdict line with evidence. Everything after this step is action, not analysis.

## Step 6 — Scope who else got it

One report almost never means one recipient. Hunt for the campaign:

1. In the Defender portal, open **Email & collaboration** → **Explorer** (`https://security.microsoft.com/threatexplorerv3`, Defender for Office 365 Plan 2; Plan 1 has the similar **Real-time detections**). Filter the **All email** view by sender address, sender domain, subject, or URL from your notes.
2. For precise or repeatable scoping, use Advanced hunting (KQL) — columns verified against the [EmailEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table):

   ```kusto
   EmailEvents
   | where Timestamp > ago(7d)
   | where SenderFromAddress =~ "sender@evil.example" or Subject has "Invoice overdue"
   | project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress,
             Subject, AuthenticationDetails, DeliveryAction, LatestDeliveryLocation, NetworkMessageId
   ```

3. Find out who *clicked* — this decides who gets a password reset in Step 7:

   ```kusto
   UrlClickEvents
   | where Timestamp > ago(7d)
   | where Url has "evil.example"
   | where ActionType == "ClickAllowed" or IsClickedThrough != "0"
   | project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId
   ```

4. Without Plan 2, scope with Exchange Online PowerShell message trace (searchable back 90 days, 10 days per query):

   ```powershell
   Get-MessageTraceV2 -SenderAddress sender@evil.example -StartDate 09/18/2026 -EndDate 09/25/2026
   ```

**Checkpoint:** You have the full recipient list, each message's `NetworkMessageId`, delivery status (inbox, junk, quarantine, blocked), and a list of users who clicked.

**Watch out:** Scope by more than one pivot. Campaigns rotate sender addresses per recipient — re-run the hunt by sending IP, subject pattern, URL domain, and attachment hash before declaring the blast radius.

## Step 7 — Purge, block, and reset

Act in this order — payload first, infrastructure second, people third:

1. **Purge the messages.** In Threat Explorer's **All email** view, select the scoped messages → **Take action** → **Move or delete** → **Soft deleted items** (user-recoverable; the usual choice) or **Hard deleted items** (purged). This requires the **Search and Purge** role (unified RBAC: **Email & collaboration advanced actions (manage)**); without it, use the wizard's **Propose remediation** → **Create new**, which queues a *soft delete* as a pending action for an admin to approve in the Action center.
2. **Block the infrastructure.** From the same **Take action** wizard, choose **Submit to Microsoft for review** → **I've confirmed it's a threat** → category **Phish**, and select the sender, domain, URLs, and attachments to add as block entries. You can also create entries directly at **Email & collaboration** → **Policies & rules** → **Threat policies** → **Rules** → **Tenant Allow/Block Lists** (`https://security.microsoft.com/tenantAllowBlockList`). Entries take effect within about 5 minutes and expire after 30 days by default (extendable to 90 or never) — matching messages are treated as high-confidence phishing and quarantined.
3. **Reset anyone who bit.** For every user from the click list who reached the page or entered credentials:
   - Reset the password.
   - Revoke active sessions so a stolen token dies with the password ([Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users.actions/revoke-mgusersigninsession)):

     ```powershell
     Revoke-MgUserSignInSession -UserId user@yourdomain.example
     ```

   - Check the mailbox for attacker persistence — new forwarding or delete rules (`Get-InboxRule` filtered on `ForwardTo`/`RedirectTo`, per the BEC section of the [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md)) — and review the user's recent sign-in logs and any new MFA registrations in Microsoft Entra.
4. **Escalate if it's bigger than email.** Confirmed credential entry, malware execution, or BEC with money in motion means you are now in incident response: switch to the [phishing playbook](/IR_PLAYBOOKS.md#phishing) and its containment/eradication flow.

**Checkpoint:** Scoped messages are out of mailboxes, block entries exist with sensible expirations, affected users are reset with sessions revoked, and anything beyond email-level response has an incident ticket.

**Watch out:** Purge *before* you block-and-notify where you can — users read fast, and a message sitting in an inbox during your paperwork is a live grenade. And never block your own domain or a shared SaaS domain (e.g., a file-sharing service) just because one campaign abused it; block the specific URLs instead.

## Step 8 — Close the loop with the reporter

The reporter is your best sensor. Treat them like one:

1. **Answer them personally, whatever the verdict.** Thank them, state the verdict in one plain sentence, and say what you did ("removed from 14 mailboxes, sender blocked"). If you manage reports on the Submissions page's **User reported** tab, you can mark the verdict and notify the reporting user from there.
2. **File the record:** verdict, evidence, defanged IOCs (sender, IPs, URLs, hashes), actions taken, and users reset — in the ticket, and into your threat-intel or watchlist process if you run one.
3. **Report it outward.** Forward phishing samples to the Anti-Phishing Working Group at `reportphishing@apwg.org` ([APWG](https://apwg.org/reportphishing/)), and use the Submissions page to report the miss to Microsoft so filtering improves for everyone.
4. **Feed the program.** A lure that beat your filters is your next awareness example and your next detection rule.

**Checkpoint:** The reporter has a reply, the ticket tells the whole story without you in the room, and the IOCs are recorded defanged.

**Watch out:** Never paste live URLs into the reply or the ticket — someone *will* click them. Defanged only, always.

## What good looks like

- The verdict is written down with its evidence — anyone can retrace it from the ticket alone.
- Scoping used at least two pivots (sender, IP, subject, URL, hash), and every delivered copy was purged or quarantined.
- Blocks exist at the right granularity (URL, sender, domain — not a whole SaaS platform) with deliberate expirations.
- Every user who clicked or replied was reset, revoked, and checked for inbox-rule persistence — not just the one who reported.
- The reporter heard back the same day; people who report and get silence stop reporting.
- Time from report to purge is minutes-to-hours, not days — measure it and trend it.

## Go deeper

**In this library:**

- [EMAIL_SECURITY_REFERENCE.md](/EMAIL_SECURITY_REFERENCE.md) — the doctrinal base: header analysis, SPF/DKIM/DMARC internals, DMARC gaps, HTML smuggling, BEC signals, M365/SEG configuration.
- [IR_PLAYBOOKS.md](/IR_PLAYBOOKS.md#phishing) — the escalation path when a phish becomes an incident.
- [INCIDENT_RESPONSE_REFERENCE.md](/INCIDENT_RESPONSE_REFERENCE.md) — the full NIST SP 800-61 response lifecycle behind Step 7's actions.
- [SOCIAL_ENGINEERING_REFERENCE.md](/SOCIAL_ENGINEERING_REFERENCE.md) — the pretexts and psychological levers phishing lures are built from.
- [DIGITAL_FORENSICS_REFERENCE.md](/DIGITAL_FORENSICS_REFERENCE.md) — deeper artifact handling when a case needs evidentiary rigor.
- [OSINT_REFERENCE.md](/OSINT_REFERENCE.md) — infrastructure research techniques for pivoting on phishing domains.

**External:**

- [CISA/NSA/FBI/MS-ISAC — Phishing Guidance: Stopping the Attack Cycle at Phase One](https://www.cisa.gov/resources-tools/resources/phishing-guidance-stopping-attack-cycle-phase-one)
- [NIST SP 800-177 Rev. 1 — Trustworthy Email](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- [Microsoft — Investigate malicious email that was delivered](https://learn.microsoft.com/en-us/defender-office-365/threat-explorer-investigate-delivered-malicious-email)
- [APWG — Report Phishing](https://apwg.org/reportphishing/)

*Guides are procedures, not doctrine: portal paths and cmdlets change — verify every command against current official documentation before relying on it in production.*
