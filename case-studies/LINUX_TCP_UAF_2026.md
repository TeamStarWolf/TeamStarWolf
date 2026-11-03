# The CVE-2026-98432 Linux Kernel Flaw and an AI-Written Exploit: A 2026 Case Study

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [AI Security](/AI_SECURITY_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [AI Threats 2026](/case-studies/AI_THREATS_2026.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)

## Executive summary

In October 2026 the Linux kernel project disclosed CVE-2026-98432, a use-after-free in the IPv4 TCP connection-setup path that a remote, unauthenticated attacker can reach by sending crafted packets to a listening socket. The kernel CNA scored it 9.8, and the upstream fix is two lines. What made this flaw a landmark was not the bug, which is an ordinary memory-safety race of a kind the kernel fixes regularly, but what Anthropic published alongside it: its Frontier Red Team reported that an unreleased internal research model, after initial prompting, wrote a working zero-click remote-root exploit against servers running a Multipath TCP listener, reaching a root shell in under an hour of model time. The exploit itself was never released.

Two facts have to be held apart, and this study keeps them apart throughout. The vulnerability is Confirmed: the kernel project, the GitHub Advisory Database, Red Hat and AWS all describe the same use-after-free and the same `kfree_rcu` fix. The AI-written exploit is Reported: it rests on Anthropic's own account, the code and test configuration were deliberately withheld, and no independent public reproduction had appeared by late October. The significance for a vulnerability management program does not depend on resolving that second question. Whether or not this particular exploit works as described, the disclosure is a credible, dated marker that the time between a memory-corruption CVE landing and a working exploit existing is collapsing toward the length of a lunch break, which changes how fast the prioritization-to-patch loop has to turn.

Evidence grade: the vulnerability is **Confirmed**; the AI-written exploit and its timing are **Reported** (single-source, Anthropic, unreleased and not independently reproduced as of this writing).

### Key findings

- **The bug is an unauthenticated remote use-after-free in IPv4 TCP.** CVE-2026-98432 (CVSS 9.8) is a race condition during concurrent processing of a retransmitted TCP connection request or a socket migration. A child socket is handed the request socket's IP options without a copy, and the options can be freed with a plain `kfree()` while the SYNACK path is still reading them under RCU, which is the use-after-free. IPv4 is affected; IPv6 is not affected by the primary issue.
- **The upstream fix is two lines.** The patch converts the two plain `kfree()` calls, in `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()`, to `kfree_rcu()`, so the options are freed only after an RCU grace period, after readers are done. It landed upstream on 5 October 2026 and was backported to the maintained stable branches, and the CVE was published on 15 October 2026.
- **Impact depends on configuration.** On a host with a Multipath TCP listener, researchers reported unauthenticated remote code execution. Without that, the reachable outcome on plain IPv4 TCP is a kernel crash, memory disclosure, or memory corruption, which is a denial of service and a possible stepping stone. Red Hat notes that reliable code execution "requires precise heap control."
- **An AI model reportedly wrote the exploit, fast, with little human steering.** Anthropic's Frontier Red Team reported that an unreleased internal model wrote the MPTCP exploit after initial prompting, taking by its own account "48 minutes to leak a kernel pointer and another five minutes to reach the shell command execution." Anthropic did not publish the exploit, the kernel version, or the configuration it tested, and framed the result as a lab exercise under coordinated disclosure, not an in-the-wild attack.
- **The ordinary triage signals still said "urgent, not on fire."** As of early November 2026 there was no reported exploitation in the wild, the CVE was not in CISA's Known Exploited Vulnerabilities catalog, and the EPSS score sat around 0.46 percent. A 9.8 base score with an AI-exploit headline and a low real-world-use signal is exactly the kind of split a prioritization program has to reconcile rather than resolve by the loudest number.

### Top recommendations

1. Patch the kernel and reboot. Apply your distribution's fixed kernel as soon as it ships and reboot, because a running kernel keeps the vulnerable code until it is replaced. Upstream fixed this on 5 October 2026, but distribution availability lagged by weeks, so confirm your own vendor's status rather than assuming "upstream fixed" means you are fixed.
2. Find your Multipath TCP exposure first. Identify hosts with an MPTCP listener, because those carry the reported remote-code-execution risk rather than denial of service, and prioritize them. Note that disabling MPTCP alone is not a complete fix: the plain IPv4 TCP path remains reachable for the crash-and-corruption outcome.
3. Use the temporary network mitigation only as a bridge. Dropping inbound IPv4 TCP packets that carry IP options (for example with an nftables rule) blunts the common trigger, but vendors are explicit that it is not a substitute for patching, it needs testing, and on container hosts it may not cover pod-to-pod traffic.
4. Reconcile the base score with the real-world signal. Treat a 9.8 with no in-the-wild use, no KEV listing, and a low EPSS as a fast-track-but-verify item: schedule it ahead of routine patching, scope it by exposure (internet-facing, MPTCP), and do not let an AI-exploit headline push it past an actively exploited bug with a lower score.
5. Shorten your own exploit-window assumptions. Plan patch SLAs for critical memory-corruption CVEs on the assumption that a working exploit can exist within hours of disclosure, for defenders and attackers alike, and that scanning your own code and dependencies before an advisory lands is now part of the job.

## Scope and method

This study covers CVE-2026-98432 as disclosed in October 2026 and the AI-exploit claim published alongside it. Sources are the kernel CVE record and GitHub Advisory Database, Red Hat, AWS and other distribution advisories, and Anthropic's own research post for the exploit claim. Each claim carries one of three evidence grades, and the AI-exploit material is held to the same bar as everything else.

| Grade | Meaning |
|---|---|
| Confirmed | The kernel project, a distribution vendor, or a government advisory confirms the vulnerability or the fix |
| Reported | A single source's account, not independently corroborated or reproduced |
| Demonstrated | A research reproduction available for others to check |

## Part 1: the vulnerability

CVE-2026-98432 lives in the kernel's handling of incoming TCP connections (**Confirmed**: kernel CNA, GitHub Advisory GHSA-qp6h-4hvh-qqqc, Red Hat, AWS). When the kernel accepts a connection, `tcp_v4_syn_recv_sock()` hands the request socket's IP options to the new child socket by pointer, without copying them. If another CPU is concurrently processing a retransmitted SYN for the same request socket, the SYNACK path reads those options while holding only `rcu_read_lock()`. Because request sockets have been processed without the listener lock since an earlier kernel change (commit `079096f103fa`), the child socket can be destroyed in the middle of that read. TCP child sockets are not marked `SOCK_RCU_FREE`, so `inet_sock_destruct()` frees the options with a plain `kfree()`, and the concurrent reader is left looking at freed memory. A second, related path exists for request-socket migration (when `net.ipv4.tcp_migrate_req` is enabled or a reuseport-migrate BPF program is attached), where the cloned request socket shares the same options pointer and `tcp_v4_reqsk_destructor()` also frees it with a plain `kfree()`.

The result is a classic use-after-free, reachable from the network before any application sees a byte, with no credentials and no user interaction. The trigger is a crafted IPv4 TCP packet carrying IP options sent to a listening socket; the migration variant needs the migration feature turned on. IPv6 is not affected by the primary issue, because `tcp_v6_syn_recv_sock()` duplicates the options rather than sharing them (the migration path has a narrower IPv6 variant tied to CALIPSO, addressed separately).

The fix is small and instructive (**Confirmed**). It changes the two offending frees to `kfree_rcu()`, so the options structures are released only after an RCU grace period, by which time any reader that entered under `rcu_read_lock()` has finished. The rationale is simply that the readers already use RCU and other option-replacement paths already deferred their frees, so the destructors should too. The change landed upstream on 5 October 2026 and was backported across the maintained stable branches; the CVE was published on 15 October 2026.

## Part 2: the AI-written exploit, graded carefully

On 28 October 2026 Anthropic's Frontier Red Team published a post describing how an unreleased internal research model found and exploited memory-safety flaws in real software, and CVE-2026-98432 was its headline Linux example (**Reported**: Anthropic). The claim has a specific, checkable shape, which is why it is worth grading rather than repeating or waving away:

- **What the model did.** Anthropic states that "after initial prompting, Claude wrote an exploit" that lets a remote attacker run commands as root, with no credentials or user interaction, on Linux servers with a Multipath TCP listener. The post attributes the work to "an unreleased, internal research model" and does not name it.
- **How fast.** By Anthropic's own account, "it takes 48 minutes to leak a kernel pointer and another five minutes to reach the shell command execution." That is the figure in dispute-free form only in the sense that it is Anthropic's measurement of its own run; it is not an independent benchmark.
- **What was withheld, and why.** Anthropic reported the vulnerabilities under its coordinated disclosure policy and did not publish the exploit code, the kernel version, or the tested configuration. It framed the exercise as a lab result, not an attack, and argued the point of publishing was to give defenders a head start, writing that "scanning your own code is more important than ever."
- **What is missing for a higher grade.** As of late October 2026 no independent party had publicly reproduced the exploit, and at least one kernel vendor team said it could not. Discovery credit for the specific CVE is also not cleanly stated: the post says "we discovered" a set of kernel findings and separately that "Claude wrote an exploit," without pinning which were model-found versus human-found, and the coordinated-disclosure report for this bug is associated with an Anthropic researcher.

The honest reading is that the exploit's existence and its sub-hour timing are a single vendor's unreproduced account, and the study grades them **Reported**, not Confirmed. That is not a dismissal. A capable lab saying, with a dated post and a real CVE number, that a model built a kernel remote-root exploit in under an hour is itself significant even before anyone reproduces it, because the direction it points is one defenders have to plan around. For the library's discipline, the useful move is to separate the two questions a reader actually has: is the bug real and reachable (yes, Confirmed), and can an AI now turn such bugs into working exploits at this speed (claimed, plausible, and the burden of the next few months is on reproduction either way). See [the AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md), whose machine-speed-vulnerability-discovery section this disclosure directly extends, and [the AI Security Reference](/AI_SECURITY_REFERENCE.md).

## Part 3: patch status and mitigation

The upstream fix existed before most organizations could deploy it, which is the usual kernel-CVE gap and the heart of the operational problem (**Confirmed**: distribution advisories, status as of late October to early November 2026):

| Ecosystem | Status |
|---|---|
| Upstream stable | Fixed on 5 October 2026 and backported across maintained stable branches |
| Debian 12 and 13 | Fixed (DLA and DSA advisories issued) |
| SUSE SLES and openSUSE Leap | Fixed for most streams; some streams still in progress |
| Oracle Linux UEK | Fixed on 16 October 2026 via ELSA advisories |
| Amazon Linux 2 and 2023 | Fixed kernel packages available; some default streams pending |
| AlmaLinux 8, 9, 10 | Patched kernels released, after a period in testing |
| Red Hat Enterprise Linux 8, 9, 10 and OpenShift | Rated Critical (9.8); Red Hat was expediting fixes and evaluating interim OpenShift guidance |
| Rocky Linux 8 to 10 and other RHEL rebuilds | Followed RHEL; no fixed kernel at the time of writing |
| Ubuntu 22.04, 24.04, 26.04, 26.10 | Fix in progress, not yet released |

Two operational points matter beyond the matrix. First, a kernel fix is not live until the host reboots into the new kernel, so "package updated" is not the same as "no longer vulnerable" for a box that has not been restarted. Second, the common temporary mitigation, an nftables rule dropping inbound IPv4 TCP packets that carry IP options, is explicitly a bridge, not a fix: Red Hat and others say it does not replace patching, it needs testing against legitimate traffic, and on OpenShift nodes it covers only the host network namespace, not pod-to-pod traffic. Disabling Multipath TCP removes the reported remote-code-execution path but leaves the plain IPv4 TCP crash-and-corruption path reachable, so it reduces severity without closing the hole.

## Cross-cutting themes

- **The exploit-availability window is the real clock.** Prioritization has always raced the moment a public exploit appears. This disclosure is a dated data point that, for memory-corruption bugs, that moment may now arrive within hours of the CVE, from an AI as readily as from a human researcher. Patch SLAs and emergency-change processes should be sized for that, not for the weeks exploit development used to take. See [the Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).
- **Base severity and real-world risk diverged, and both were right.** A uniform 9.8 said the bug is as bad as bugs get in principle; the empty KEV entry and low EPSS said no one was using it yet; the MPTCP condition said the worst outcome only applied to some hosts. A program that collapses these into one number, in either direction, mis-triages. The job is to carry all three and act on their combination.
- **AI capability claims deserve the same evidence grading as everything else.** The right response to a vendor saying its model built a kernel exploit is neither to treat it as proven nor to dismiss it as marketing, but to grade it (single-source, unreproduced, Reported), act on the part that is already certain (the patch), and watch for reproduction. This is the same Confirmed-versus-Reported discipline the rest of the library applies to threat claims. See [the AI Security Reference](/AI_SECURITY_REFERENCE.md) and [Fuzzing and Vulnerability Research](/FUZZING_VULNERABILITY_RESEARCH.md).
- **Defenders can run the same tools.** If a model can find and chain memory-safety bugs at this speed, the defensive implication Anthropic itself drew is that scanning your own code and dependencies before an advisory lands is now table stakes, not an advanced practice. The capability is dual-use; the question is who runs it first on your code.

## Sources

- The Linux kernel CVE record for CVE-2026-98432 and the GitHub Advisory Database entry GHSA-qp6h-4hvh-qqqc, including the root-cause description, the `kfree_rcu` fix, the CVSS 9.8 vector, and the IPv6 note.
- Red Hat's vulnerability page and security bulletin RHSB-2026-016 for CVE-2026-98432, for the Critical rating, the affected Red Hat Enterprise Linux and OpenShift versions, the "requires precise heap control" statement, and the nftables mitigation guidance.
- The AWS security bulletin for CVE-2026-98432, for the affected-version range, the Multipath TCP remote-code-execution statement, its statement that there was no evidence of exploitation in the wild, and the Amazon Linux fix status.
- Distribution advisories from Debian, SUSE, Oracle, AlmaLinux, Rocky Linux and Ubuntu, and vendor trackers, for the patch-status matrix.
- Anthropic's Frontier Red Team research post, "Discovering and exploiting vulnerabilities in critical, real-world software with Claude," for the exploit claim, the model description, the timing figures, and the coordinated-disclosure framing; the exploit, kernel version and configuration were not published, and the claim was not independently reproduced as of this writing.

## Related references

- [AI Security Reference](/AI_SECURITY_REFERENCE.md)
- [MITRE ATLAS Reference](/ATLAS_REFERENCE.md)
- [Fuzzing and Vulnerability Research](/FUZZING_VULNERABILITY_RESEARCH.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [The AI Threats 2026 Case Study](/case-studies/AI_THREATS_2026.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
