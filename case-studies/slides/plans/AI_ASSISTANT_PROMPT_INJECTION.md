# Slide plan: When the Assistant Has Tools: Prompt Injection in Six AI Assistants

- Study: case-studies/AI_ASSISTANT_PROMPT_INJECTION.md
- Cover title: When the Assistant Has Tools / Prompt Injection Across Six / AI Assistants
- Subtitle: Six named products, five public cases of prompt injection, and why the assistant's tools, not its chat, are the attack surface
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/AI_ASSISTANT_PROMPT_INJECTION.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The assistant that reads and acts

- An assistant that reads untrusted content and holds tools is a new attack surface: it reads an email, a message, a page or a file, and it can also act.
- The shared flaw: a model does not reliably separate its operator's instructions from the data it processes, so instructions planted in that data get followed.
- Five public cases across six named products, two with a CVE and three without.
Caption: Evidence grade: Confirmed for the CVE records; Reported for the finder write-ups. Scores are attributed to whoever assigned them.
Notes: EchoLeak [1]. Slack AI [3]. Rules File [4]. vanna [2][5]. ChatGPT [6][7]. The framing is the study's (Inferred).

## THE PATTERN | What ties the cases together

- **Prompt injection.** The model follows instructions found in its input; when the input is retrieved on its own, it is indirect prompt injection.
- **The tool is the risk.** Harm comes from what the assistant can do beyond chatting: render a link, emit and run code, write a memory, reach a connector.
- **A confused deputy.** The assistant acts with the user's reach, on content an attacker controls, and cannot tell whose instruction it follows.
Caption: A fixed flaw closes one path. The design property, that a model acts on its input, is managed by the controls around the assistant, not a patch.
Notes: Mechanism described by each source [3][4][5][6][7]. Confused-deputy framing is the study's (Inferred).

## KEY FACTS | The products, the records, the scores

Stat: 6 | named products in the record
Stat: 9.3 | Microsoft's CVSS for EchoLeak
Stat: 8.1 | JFrog's CVSS for the vanna RCE
Stat: 2 of 5 | cases that carry a CVE
- With a CVE: Microsoft 365 Copilot (CVE-2025-32711) and the vanna library (CVE-2024-5565).
- Without a CVE: Slack AI, the Rules File Backdoor in GitHub Copilot and Cursor, and the ChatGPT memory and connector write-ups.
Notes: 9.3 is Microsoft's own score [1]; 8.1 is JFrog's [2]. The three without a CVE carry the finder's characterization, not an assigned score [3][4][6][7].

## PART 1 | EchoLeak, Microsoft 365 Copilot

- Microsoft's record (CVE-2025-32711) calls it an AI command injection in Microsoft 365 Copilot that lets an unauthorized attacker disclose information over a network.
- Microsoft scores it 9.3 Critical (CVSS 3.1), no privileges and no user interaction in the vector, weakness CWE-74.
- The name EchoLeak is the finder's (Aim Labs), tied to the CVE by the record's reference.
Caption: The remediation level is an official fix, applied on the service side. The finder's write-up was not reachable, so no attack chain is shown.
Notes: All from the CVE record [1]. Aim Labs page returned 403, so no attack chain is described. Server-side delivery is Inferred.

## PART 2 | Slack AI data exfiltration

- PromptArmor (14 August 2024): an instruction placed in an attacker-made public channel can steer Slack AI to leak data from private channels the attacker cannot see.
- Slack AI retrieves from public channels a user has not joined; a public channel can be made with only its author, so it goes unnoticed.
- The assistant renders a link worded as a reauthentication prompt that carries the victim's value; clicking it sends the value out.
Caption: Slack deemed the evidence insufficient and called the cross-channel retrieval intended behaviour; no fix. No payload is reproduced here.
Notes: Mechanism and Slack's quoted response [3]. The 14 August change also let Slack AI ingest files, widening the surface [3].

## PART 3 | The Rules File Backdoor, GitHub Copilot and Cursor

- Pillar Security (18 March 2025): hidden, non-rendering Unicode instructions in a shared rule or config file steer a coding assistant to insert attacker-chosen code.
- The file is trusted implicitly and the malicious code is hard to spot in review; Pillar frames it as a supply-chain vector.
- Affects the two named editors, GitHub Copilot and Cursor.
Caption: Cursor and GitHub called review the user's job; GitHub added a hidden-Unicode warning on github.com on 1 May 2025. No rule content is shown.
Notes: Mechanism and the disclosure timeline, including both vendors' positions [4].

## PART 4 | Remote code execution in the vanna library

- JFrog (CVE-2024-5565, 31 May 2024): the library's ask method generates and runs plotting code for a visualization.
- Untrusted input with the visualization option at its default can steer the model to return attacker-chosen Python instead, which the library runs.
- Scored 8.1 High (CVSS 3.1) by JFrog, weakness CWE-94; the finder reports proving code execution.
Caption: JFrog's advisory gives a workaround, not a vendor fix: set visualization off on any path with external input. It names no fixed release.
Notes: Score and CWE from the CVE record [2]; mechanism, workaround and the silence on a maintainer fix from JFrog's advisory [5].

## PART 5 | ChatGPT memory and connectors

- Rehberger (22 May 2024): untrusted content ChatGPT reads can make it write or delete long-term memories that then persist into later chats.
- OpenAI closed that report as a model-safety issue, not a security vulnerability.
- Rehberger (1 August 2025): a separate flaw let an injected instruction send chat history and memories to an attacker-readable host; OpenAI addressed it by 26 August 2025.
Caption: Two halves of one problem: untrusted input can write a store that outlives the chat, and a separate flaw let data in the chat leak out.
Notes: Memory write path and OpenAI's close [6]; the url_safe exfiltration path and the fix note [7]. No payload is reproduced.

## PART 6 | Four different vendor answers

| Vendor | What they did | What it means |
|---|---|---|
| Microsoft | Recorded the flaw; record shows an official fix | Fixed on the service side |
| GitHub | Added a hidden-Unicode warning; review is the user's job | A control, plus a user-responsibility position |
| Cursor, Slack | Called it the user's responsibility or intended | Not treated as their flaw to fix |
| OpenAI | Closed memory write as model-safety; later fixed a leak path | A partial answer across two reports |
Caption: A report does not always lead to a patch. A defender has to know which controls the vendor left to the user.
Notes: Microsoft [1]; GitHub and Cursor [4]; Slack [3]; OpenAI [6][7].

## DEFENDER VIEW | Find and fix, read-only first

Left: What to read
- Which assistants are in use, what each can read, and what each can do (tools, connectors, code paths).
- Where untrusted input can reach a tool: a retrieval source, a shared config file, a generation-and-execution path.
- Whether memory and connectors are on, and what they can reach.
Right: What to do
- Apply the fix where one exists (Microsoft 365 Copilot; the GitHub warning control).
- Follow the workaround where that is all there is (vanna: visualization off on external input).
- Treat the assistant's output as untrusted; scope connectors and keys narrowly.
Caption: Where a vendor called the behaviour intended or the user's responsibility, record that as the accepted state of the control, not a closed ticket.
Notes: Per-product steps from [1][3][4][5][6]. Read-first and output-as-untrusted are the study's framing (Inferred).

## MITRE MAPPINGS | A small, honest table

| Id | Technique | Tie to the record |
|---|---|---|
| T1195 | Supply Chain Compromise | The Rules File Backdoor, planted in a shared config file that reaches many projects |
| T1059 | Command and Scripting Interpreter | The vanna flaw runs attacker-chosen Python through the library |
| T1567 | Exfiltration Over Web Service | Slack AI and ChatGPT move data to an attacker host through a rendered link or request |
Caption: ATT&CK v20.0. The enterprise catalog does not model an LLM following instructions in its input, so prompt injection itself is left unmapped.
Notes: Names and tactics from library data [8]; ties from [3][4][5][7]. CWE-74 [1] and CWE-94 [2] are the records' weakness labels. MITRE ATLAS covers this class; this study maps only ATT&CK.

## CROSS-CUTTING THEMES | What the record teaches

- **One cause, five shapes.** Disclosure, exfiltration, injected code, library RCE and memory tampering all rest on the model acting on its input.
- **Vendors disagree on ownership.** Two shipped or recorded a fix; three moved the control to the user, who then has to know it is theirs.
- **The durable defence is the classic one.** Narrow what the deputy can read, what it can do, and how far its credentials reach.
Notes: Shared cause [3][4][5][6][7]. Vendor split [1][3][4]. Confused-deputy defence is the study's framing (Inferred).
