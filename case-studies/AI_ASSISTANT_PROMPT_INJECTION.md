# When the Assistant Has Tools: Prompt Injection in Microsoft 365 Copilot, Slack AI, GitHub Copilot, Cursor, vanna and ChatGPT

*A TeamStarWolf case study. Published 25 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [AI Offensive Security](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [Internet-Facing Services](/INTERNET_FACING_SERVICES_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security engineers, application and platform owners who have added an AI assistant, incident responders, and anyone deciding what an assistant may read and do

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 21 min (4,786 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run an AI assistant that reads untrusted content or holds tools and connectors (Microsoft 365 Copilot, Slack AI, GitHub Copilot, Cursor, a library such as vanna, or ChatGPT), or you need the facts behind the public prompt-injection record

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 6: Find and fix](#part-6-find-and-fix), [Part 7: Weakness and technique mapping](#part-7-weakness-and-technique-mapping)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

An AI assistant that reads untrusted content and holds tools is a new kind of attack surface. The assistant reads an email, a document, a chat message, a web page or a source file, and it can also act: render a link, call a connector, write to a memory, or emit code that runs. The flaw that ties the cases below together is that a language model does not reliably separate the instructions its operator gave it from the data it is asked to process, so instructions planted in that data can be followed. This is prompt injection, and when the planted instructions arrive through content the assistant retrieves on its own, it is indirect prompt injection (Inferred, as the study's framing; the mechanism is described by each source below).

This study reads the public record of five such cases across six named products: the EchoLeak flaw in Microsoft 365 Copilot (CVE-2025-32711); the Slack AI data-exfiltration technique PromptArmor reported; the Rules File Backdoor in GitHub Copilot and Cursor, reported by Pillar Security; the remote code execution flaw in the vanna library (CVE-2024-5565); and the memory and connector exfiltration write-ups for ChatGPT by Johann Rehberger. Two of the cases carry a CVE and a CVSS score from an assigning authority: Microsoft's for EchoLeak, where Microsoft is also the vendor, and JFrog's for vanna, where JFrog is the finder and an assigning authority but not the library's maintainer. The vanna flaw also carries a second CVE from a different authority, @huntr_ai, scored higher. The other three cases have no CVE, so their severity is the finder's characterization, not an assigned score (Confirmed [1][2][11]; Reported for the cases [3][4][5][6][7]).

The vendors answered these in different ways, and the study keeps each in its own words. Microsoft recorded a flaw and its record shows an official fix (Confirmed [1]). GitHub, after the report, said users are responsible for reviewing what the assistant suggests, then added a warning control (Reported [4]). Cursor said the risk falls under the user's responsibility and was not a vulnerability on its side (Reported [4]). Slack's first reply deemed the evidence insufficient and called the cross-channel retrieval intended behaviour, but Slack then published a security update stating it had deployed a patch on 20 August 2024 (Reported [3][9]). OpenAI closed the memory report with the label model-safety issue rather than a security vulnerability, and a separate exfiltration path was later addressed (Reported [6][7]). Where a source gives no detail, this study says so.

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| Products named | Microsoft 365 Copilot, Slack AI, GitHub Copilot, Cursor, the vanna library, ChatGPT | Confirmed for the two in the CVE records [1][2]; Reported for the rest [3][4][5][6][7] |
| Cases with a CVE | CVE-2025-32711 (Microsoft 365 Copilot); CVE-2024-5565 and CVE-2024-5826 (the vanna flaw, two CVEs) | Confirmed [1][2][11] |
| CVSS, and whose | 9.3 Critical, CVSS 3.1, assigned by Microsoft (EchoLeak); for the vanna flaw, 8.1 High, CVSS 3.1, from JFrog (CVE-2024-5565) and 9.8 Critical, CVSS 3.0, from @huntr_ai (CVE-2024-5826) | Confirmed [1][2][11] |
| Cases without a CVE | Slack AI, the Rules File Backdoor, the ChatGPT memory and connector write-ups | Inferred, since the write-ups cite no CVE [3][4][6][7] |
| Shared mechanism | A model follows instructions planted in the content it processes (prompt injection; indirect when the content is retrieved) | Reported across [3][4][5][6][7] |
| Vendor outcome | Microsoft recorded a fix [1]; OpenAI closed the memory report as a model-safety issue and the url_safe path was later addressed [6][7]; GitHub said users are responsible, then added a warning [4][12]; Cursor said the user's responsibility [4]; Slack called the retrieval intended, then deployed a patch on 20 August 2024 [3][9]; the vanna maintainer added a hardening guide after disclosure, with no fixed release named [5][10] | Confirmed [1][12]; Reported [3][4][5][6][7][9][10] |
| Public exploitation detail | None of the sources reviewed reports in-the-wild exploitation against a named victim | Inferred from [1][2][3][4][5][6][7] |

### Key findings

- **One root cause, five shapes.** Information disclosure from an enterprise assistant, data exfiltration from a workspace assistant, malicious code inserted by a coding assistant, code execution inside a library, and persistent memory tampering all rest on the same fact: the model acts on instructions found in its input (Reported [3][4][5][6][7]).
- **The tool is the risk, not the chat.** The damage in each case comes from something the assistant can do beyond answering: render a link, emit and run code, write a memory, reach a connector. An assistant with no tools and no retrieval has far less to offer an attacker (Inferred).
- **Reachability varies sharply.** The vanna flaw needs untrusted input to reach a code path; the Rules File Backdoor needs a poisoned shared config file to be trusted; EchoLeak is scored as needing no privileges and no user interaction; the Slack AI chain needs the attacker to be in the workspace, the victim to ask Slack AI for the data, and the victim to click the rendered link (Confirmed [1]; Reported [3][4][5]).
- **Vendors disagree on whose problem this is.** Microsoft recorded a fix; OpenAI closed the memory report and later addressed the url_safe path; GitHub said users are responsible, then added a warning; Cursor said the user's responsibility; Slack called the retrieval intended, then deployed a patch; and the vanna maintainer added a hardening guide after disclosure. A defender cannot assume a report leads to a patch, nor assume it does not (Confirmed [1]; Reported [3][4][5][6][7][9][10]).
- **Exploitation scope is not public.** The records establish the flaws, and each of the five write-ups demonstrates its technique under stated conditions. None of the sources reviewed names a real-world victim or a campaign (Demonstrated [3][4][5][6][7]; Inferred for the absence of victims).

### Top recommendations

1. Inventory where an assistant reads untrusted content and what it can do with it: which assistants are in use, what each can retrieve, and which tools, connectors or code paths each can reach.
2. Treat the assistant's output as untrusted. A link, an image, a code suggestion or a tool call produced from untrusted input deserves the same scrutiny as input from the internet.
3. Keep secrets out of places an assistant can read, and scope connectors and tokens to the minimum. A proxy or workspace that holds many keys is a high-value target once the assistant can be steered.
4. For a coding assistant, review generated changes against the diff, not the model's summary, and watch for any warning that flags hidden or non-rendering characters in files, such as the one GitHub shows on github.com.
5. Apply the fix where one exists (Microsoft 365 Copilot's service-side fix); use the controls a vendor added, such as GitHub's hidden-Unicode warning, which is a warning and not a fix; and where the vendor offers only a setting or a workaround, record that as the accepted state of the control rather than a closed ticket.

## Scope and evidence standard

This study uses the two CVE records (for CVE-2025-32711 and CVE-2024-5565), PromptArmor's Slack AI write-up, Pillar Security's Rules File Backdoor write-up, JFrog's vanna advisory, and Johann Rehberger's two ChatGPT write-ups. It names only the six products above. No exploit was run, and no prompt, payload or step-by-step is reproduced here, even where a finder published one; each mechanism is described in words.

**Confirmed** means an official record (a CVE record, a vendor page) supports the claim. **Reported** means a finder's or third party's write-up stated it without an independent official record. **Demonstrated** marks a capability a finder says it proved under stated conditions. **Inferred** marks the author's interpretation. A statement that a source gives no detail is a statement about that source, not about the world.

One source could not be opened. The finder write-up for EchoLeak, hosted by Aim Labs, returned HTTP 403 to every attempt for this study, so Part 1 rests on the CVE record alone and does not reproduce the finder's attack chain. A CVSS score measures severity under a stated vector; it does not measure exploitation. These distinctions carry through the sections below.

For each vendor, this study also checked the vendor's own channel for a statement dated after the finder's write-up. Microsoft's CVE record carries the official fix; Slack published a security update; GitHub published a changelog entry; and JFrog's write-up records the vanna maintainer's hardening guide (each a numbered source below). No later statement was found on Cursor's security page (cursor.com/security) or OpenAI's security page (openai.com/security-and-privacy), both opened 25 November 2026; OpenAI's responses in this study are as the finder reports them (Reported for the finder's account [6][7]; Inferred for the absence of a vendor page). This study does not conclude that a vendor did nothing where it found no page.

## Part 1: EchoLeak, Microsoft 365 Copilot (CVE-2025-32711)

### What the record says

Microsoft is the assigning authority for CVE-2025-32711, which it titles an M365 Copilot information disclosure vulnerability and describes as an AI command injection in Microsoft 365 Copilot that allows an unauthorized attacker to disclose information over a network. Microsoft scores it 9.3 (Critical) under CVSS 3.1, with the vector marking network reach, low attack complexity, no privileges required and no user interaction, and a scope change. It classes the weakness as CWE-74, improper neutralization of special elements in output used by a downstream component, the injection family. The record was published on 11 June 2025 (Confirmed [1]).

The name EchoLeak is the finder's, not Microsoft's. The CVE Program record carries a reference to the Aim Labs write-up that reported and named the flaw, which is how this study ties the two together (Confirmed [1]).

### What is not public here

This study could not open the Aim Labs write-up, so it does not describe the attack chain, the content that carried the injection, or what exactly was disclosed beyond the record's own words. What the record supports is the shape: an injection flaw in an assistant that reads a user's own tenant data, reachable over the network, with no privileges and no user interaction in the scored vector, leading to information disclosure (Confirmed [1]). The detail beyond that is in a source this study could not reach, and the study does not fill the gap.

### Exploitation status and what Microsoft did

The record's scored vector marks the remediation level as an official fix and the exploit maturity as unproven, and CISA's SSVC entry, dated 14 June 2025, marks exploitation none, automatable yes and technical impact total (Confirmed [1]). Because Microsoft 365 Copilot is a cloud service, a fix of this kind applies on Microsoft's side without an action by the customer, which is consistent with the record carrying a fix but naming no customer patch version (Confirmed [1]; Inferred for the server-side delivery). The record names no victim, no actor and no observed exploitation.

## Part 2: Slack AI data exfiltration (PromptArmor)

### The product and the technique

Slack AI is a feature that answers natural-language questions over a workspace's Slack messages. PromptArmor published this on 20 August 2024, after a private disclosure to Slack on 14 August: that Slack AI could be made to exfiltrate data from private channels the attacker is not a member of, through an indirect prompt injection posted in a public channel (Reported [3]).

The technique rests on two facts the write-up sets out. First, Slack AI retrieves from public channels across the workspace, including public channels the querying user has not joined, which the write-up quotes Slack as calling intended behaviour. Second, a public channel can be created with only its author as a member, so it is unlikely to be noticed. An instruction placed in such a channel is retrieved into the same context as a user's own query, and the model can follow it (Reported [3]).

### The mechanism, in words

The planted instruction tells the assistant that, when a user asks for their own sensitive value, it should answer with a short message worded as a reauthentication prompt, rendered as a clickable link, and should place the user's value into the link's address. When the victim asks the assistant for their own data and then clicks the link, the value travels to the attacker's host as part of the request. The write-up also notes a citation gap: in the demonstration the answer cited only the victim's own channel, not the attacker's, so the source of the injected instruction was hidden; it adds that this was not consistent, calling the citation behaviour fairly stochastic, since in another run Slack AI did cite the attacker's channel. This study describes the effect and reproduces none of the instruction text (Reported [3]).

PromptArmor adds that a change on 14 August 2024 let Slack AI also ingest uploaded files and connected documents, which widens where an injection can come from: an instruction hidden in a file a user uploads means the attacker may not even need to be in Slack. PromptArmor notes it did not test this path explicitly, since its testing predated the change, and that Slack lets owners and admins restrict Slack AI's ingestion of documents (Reported [3]).

### What Slack did

Slack's security team engaged over several days, then, on 19 August 2024, deemed the evidence insufficient and stated that messages posted to public channels can be searched and viewed by all members of a workspace whether or not they have joined the channel, which is intended behaviour. Slack's reason was that in the first demonstration video the queried data had been posted to the public test channel, so the retrieval shown was expected (Reported [3]).

Slack's public position followed, and it is different from the first reply. In a security update dated 21 August 2024, Slack wrote that it had deployed a patch to address the reported issue on 20 August 2024 and had no evidence at that time of unauthorized access to customer data; it describes the scenario as one where, under very limited and specific circumstances, a malicious actor with an existing account in the same workspace could phish users for certain data. Slack does not say what the patch changed, so this study records that a patch was deployed without describing its effect, and keeps the cross-channel retrieval, which Slack still calls intended, separate from the exploit the patch addressed (Reported [9]).

## Part 3: The Rules File Backdoor, GitHub Copilot and Cursor (Pillar Security)

### The technique

On 18 March 2025, Pillar Security reported a technique it named the Rules File Backdoor, affecting the AI code editors Cursor and GitHub Copilot. A rule file is a shared configuration file that guides an assistant's behaviour when it generates or edits code; these files are stored in central repositories, distributed through open-source communities, and trusted implicitly as harmless configuration (Reported [4]).

The technique hides malicious instructions inside such a file using non-rendering Unicode characters and other evasion, so a reviewer reading the file sees nothing unusual. An assistant that loads the poisoned rule file can then be steered to insert attacker-chosen code into what it generates, code that a developer is unlikely to catch because it came from a trusted assistant following a trusted config. Pillar frames this as a supply-chain vector: one poisoned file can reach every project that adopts it. Two points make detection hard: the hidden instructions also tell the assistant not to mention the change, so its reply to the developer gives no sign of it and nothing appears in the chat history or logs; and the non-rendering characters stay invisible in GitHub's pull-request approval review. The write-up reports and demonstrates this against the two named editors; this study describes the effect and reproduces no rule-file content (Reported [4]; Demonstrated [4]).

### What the vendors did

Pillar's disclosure timeline records two different answers. Cursor was contacted on 26 February 2025, replied that it was investigating, and by 6 to 8 March 2025 determined that the risk falls under the user's responsibility and that it is not a vulnerability on Cursor's side. GitHub was contacted on 12 March 2025, replied the same day that users are responsible for reviewing and accepting the suggestions Copilot generates, and, following the research, on 1 May 2025 added a feature that displays a warning when a file's contents include hidden Unicode text on github.com (Reported [4]). GitHub's own changelog confirms the control: a 1 May 2025 entry states that a warning is now displayed when a file's contents include hidden Unicode text on github.com, and references Pillar's Rules File Backdoor (Confirmed for the control [12]; it is a warning, not a fix).

So one vendor shipped a detection aid for the specific evasion while holding that review is the user's job, and the other held the same position without a named control. Neither treated the assistant's trust in a poisoned config as a flaw to fix in the assistant itself (Reported [4]; Inferred for the reading).

## Part 4: Remote code execution in the vanna library (CVE-2024-5565)

### The flaw

JFrog is the assigning authority for CVE-2024-5565, published on 31 May 2024, in the vanna library, a Python package that turns natural-language questions into SQL and visualizations. The record describes a prompt injection in the library's ask interface that leads to remote code execution, scores it 8.1 (High) under CVSS 3.1, classes the weakness as CWE-94, improper control of generation of code, marks every version affected (version 0 upward) with no fixed version named, and carries a CISA SSVC entry marking exploitation proof-of-concept (Confirmed [2]). JFrog's own advisory attributes the finding to Natan Nehorai of JFrog (Reported [5]). The same flaw carries a second CVE, CVE-2024-5826, assigned by @huntr_ai and published on 27 June 2024 for an independent report, which scores it 9.8 (Critical) under CVSS 3.0 with the same weakness, CWE-94, and the same proof-of-concept exploitation marking; so two assigning authorities scored one flaw 8.1 and 9.8 (Confirmed [11]; the independent discovery is Reported [10]).

### The mechanism, in words

The library's ask method can produce a visualization, and to do so it has the model generate plotting code that the library then runs. When untrusted text reaches that method with the visualization option left at its default, the text can steer the model into returning attacker-chosen Python instead of plotting code, and the library runs it. The result is code execution in the process that hosts the library. This study describes the path and reproduces no prompt or code (Reported [5]; Demonstrated [5] for the finder's proof of execution).

### What the record says to do

JFrog's advisory gives a workaround rather than a vendor fix: when the ask interface is used with external input, set the visualization option to off, which keeps the untrusted path away from the code-generation step. The advisory names no fixed release. JFrog's own write-up records a vendor response: after disclosure, the vanna maintainer added a hardening guide to educate users about preventing such attacks (Reported [10]). This study could not open vanna's hardening-guide documentation, which returned a 404 when checked on 25 November 2026, so it reports the guide only as JFrog describes it; no fixed release is named in either source (Reported [5][10]).

## Part 5: ChatGPT memory and connectors (Johann Rehberger)

### Writing to memory from untrusted content

ChatGPT's memory feature stores facts across conversations and, as the write-up notes, is on by default. On 22 May 2024, Johann Rehberger reported that when ChatGPT processes untrusted content, such as a connected document, an uploaded image or a browsed web page, that content can induce the assistant to call the memory tool and write entries the user did not ask for, or delete existing ones. Because memories are carried into later conversations, a planted memory persists beyond the one chat (Reported [6]).

OpenAI closed the report with the label "Model Safety Issue"; by the finder's account it was not treated as a security vulnerability, and no statement from OpenAI is quoted (Reported [6]). The finder reports the connected-document path working well and persisting across chats, while a browsing-based variant was less reliable, proving the point only a few times; the finder saw partial mitigations added to the browsing path and none for the image and connected-document paths at the time of writing (Reported [6]).

### Getting data back out

In a second write-up, dated 1 August 2025, Rehberger describes a data-exfiltration path. ChatGPT has a protection, called url_safe, meant to stop data leaving a chat through links and images that render to untrusted hosts. The write-up reports that some domains on the protection's allowlist accept requests into storage an attacker can read, so an injected instruction can place content from the conversation, including chat history and memories, into a request to such a domain. The finder reports the bypasses were reported to OpenAI in October 2024, notes that the root cause was reported to OpenAI over two years earlier and keeps recurring, and adds an update dated 26 August 2025 stating that the issue has now been addressed by OpenAI. This study describes the path and reproduces no payload (Reported [7]).

Taken together, the two write-ups show both halves of a persistence-and-exfiltration problem on a consumer assistant: untrusted content can write to a store that outlives the chat, and a separate flaw let data in the chat be sent out (Reported [6][7]; Inferred for the pairing).

## Part 6: Find and fix

### Decide where an assistant reads untrusted input and what it can do

For each assistant in use, write down two things: what it can read, and what it can do. For Microsoft 365 Copilot, that is tenant content it retrieves on a user's behalf; keep it patched as a cloud service and apply the controls Microsoft documents. For Slack AI, record whether it is enabled, and review the workspace settings that govern what it ingests and which channels it searches, since the retrieval behaviour is by design. For a coding assistant such as GitHub Copilot or Cursor, record where rule and configuration files come from and whether they are reviewed before adoption. For a library such as vanna, find where untrusted input can reach a generation-and-execution path. For ChatGPT, record whether memory and connectors are on and what they can reach (Inferred from [1][3][4][5][6]).

### Apply the fix, the control, or the workaround

Match the response to what the vendor offered. Microsoft 365 Copilot carries an official fix applied on the service side. On github.com, watch for the hidden-Unicode warning GitHub added, which is a warning and not a fix, and review generated changes against the diff rather than the assistant's summary. For vanna, follow JFrog's workaround and keep the visualization option off on any path that takes external input. For ChatGPT, where OpenAI declined to treat memory writes as a vulnerability, the finder's advice is the control that remains: watch for the "Memory updated" notice and inspect what the assistant has stored (Reported [6]); limiting what the assistant may read and scoping connectors narrowly is this study's addition (Inferred). Where the vendor has called the behaviour the user's responsibility, as Cursor did, record that as the accepted state of the control, not a fix; where a vendor patched after first declining, as Slack did, record the patch even though the vendor did not say what it changed (Confirmed [1]; Reported [3][4][5][6][7][9]).

### The treat-the-output-as-untrusted view

The common thread for defenders is to stop trusting an assistant's output just because it came from the assistant. A link it renders, an image it embeds, a memory it writes, a connector it calls or code it emits can each carry an instruction the assistant read in untrusted content. The useful controls sit around the assistant: what it is allowed to read, what tools it holds, how its output is reviewed, and how tightly its credentials are scoped (Inferred).

## Part 7: Weakness and technique mapping

The mapping below is this study's interpretation of public definitions, checked on 25 November 2026. It is deliberately small, because the enterprise ATT&CK catalog was not built to describe a language model following instructions in its input.

| Label | Case support | Boundary |
|---|---|---|
| CWE-74 (CVE-2025-32711) | Assigned by Microsoft for the Microsoft 365 Copilot injection flaw | The authoritative weakness label [1] |
| CWE-94 (CVE-2024-5565) | Assigned by JFrog for the vanna code-generation flaw | The authoritative weakness label [2] |
| [T1195 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/) | The Rules File Backdoor, planted in a shared config file that reaches many projects | Analytical mapping; Pillar frames it as a supply-chain vector [4][8] |
| [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | The vanna flaw runs attacker-chosen Python through the library | High-confidence analytical mapping [2][5][8] |
| [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) | The Slack AI and ChatGPT cases move data to an attacker host through a rendered link or a request | Analytical mapping [3][7][8] |
| [T1204 User Execution](https://attack.mitre.org/techniques/T1204/) | The Slack AI chain needs the victim to click the rendered link [3] | Analytical mapping; the ChatGPT url_safe path instead renders an image that sends the data, needing no click, though the assistant must still process the attacker's content (Reported [7]; Inferred for the no-click reading) [8] |
| Prompt injection itself | No enterprise ATT&CK technique models an LLM following instructions in its input | Not mapped here; MITRE ATLAS covers this class, but this study maps only the library's ATT&CK data [8] |

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is to read these cases as one failing assistant or one broken vendor. They are six products, five finders (PromptArmor, Pillar Security, JFrog, Johann Rehberger and Aim Labs), and vendor answers that differ, tied only by a shared mechanism (Inferred). The easy understatement is to dismiss a case because the vendor called it the user's responsibility: Cursor's user-responsibility position does not make the poisoned-config behaviour stop working, and it moves the control to the user, who then has to know it is theirs to hold. Slack shows the other side: it first called the retrieval intended and then patched the reported exploit, so a first reply is not a vendor's last word (Reported [3][4][9]).

### The assistant as a confused deputy

The pattern under all five cases is an old one in a new place. The assistant acts with the user's reach, on content the attacker controls, and cannot tell whose instruction it is following. That is a confused-deputy problem, and the durable defence is the classic one: reduce what the deputy can be tricked into doing by narrowing what it can read, what it can do, and how far its credentials reach (Inferred). A fixed flaw, like EchoLeak, closes one path; the design property, that a model follows instructions in its input, is not closed by a patch and is managed by the controls around the assistant.

## Sources

1. CVE Program, CVE Record CVE-2025-32711 (Microsoft CNA; the CVE Program Container carries the Aim Labs EchoLeak reference; the CISA ADP container carries the SSVC entry). https://www.cve.org/CVERecord?id=CVE-2025-32711
2. CVE Program, CVE Record CVE-2024-5565 (JFrog CNA; CISA ADP container). https://www.cve.org/CVERecord?id=CVE-2024-5565
3. PromptArmor, Data Exfiltration from Slack AI via Indirect Prompt Injection, 20 August 2024. https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection
4. Pillar Security (Ziv Karliner), New Vulnerability in GitHub Copilot and Cursor: How Hackers Can Weaponize Code Agents, 18 March 2025. https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents
5. JFrog Security Research (Natan Nehorai), Vanna prompt injection RCE (JFSA-2024-001034449), 31 May 2024. https://research.jfrog.com/vulnerabilities/vanna-prompt-injection-rce-jfsa-2024-001034449/
6. Johann Rehberger (Embrace The Red), ChatGPT: Hacking Memories with Prompt Injection, 22 May 2024. https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/
7. Johann Rehberger (Embrace The Red), Exfiltrating Your ChatGPT Chat History and Memories With Prompt Injection, 1 August 2025. https://embracethered.com/blog/posts/2025/chatgpt-chat-history-data-exfiltration/
8. TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings. https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack
9. Slack, Slack Security Update, 21 August 2024, for the patch deployed on 20 August 2024 and Slack's description of the scenario. https://slack.com/blog/news/slack-security-update-082124
10. JFrog Security Research, When Prompts Go Rogue: Analyzing a Prompt Injection Code Execution in Vanna.AI, 27 June 2024, for the vendor response (the maintainer's hardening guide) and the independently assigned second CVE. https://jfrog.com/blog/prompt-injection-attack-code-execution-in-vanna-ai-cve-2024-5565/
11. CVE Program, CVE Record CVE-2024-5826 (@huntr_ai CNA; CISA ADP container), the second CVE for the vanna flaw. https://www.cve.org/CVERecord?id=CVE-2024-5826
12. GitHub Changelog, GitHub now provides a warning about hidden Unicode text, 1 May 2025. https://github.blog/changelog/2025-05-01-github-now-provides-a-warning-about-hidden-unicode-text/

## Related references

- [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md) for the wider record of attacks on and with AI systems.
- [CVE Reference](/CVE_REFERENCE.md) and [CWE Reference](/CWE_REFERENCE.md) for the identifiers used here.
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md) for treating an exposed assistant or management interface as attack surface.
