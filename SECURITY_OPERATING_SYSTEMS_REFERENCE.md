# Security Operating Systems and Distributions

This reference catalogs the operating systems and distributions that matter in security work: the offensive and forensic distributions analysts run, the privacy and anonymity systems, and the hardened and minimal operating systems that reduce attack surface in production. For each it gives what the system is for and what it is built on, because the base distribution, kernel, and package manager decide how it is patched and assessed.

| Attribute | Value |
|---|---|
| Categories | Offensive, forensic, privacy, hardened and minimal, general-purpose |
| Per entry | Purpose, base, package manager, update model |
| Why it matters | The base decides the patch path, the package format, and the CVE feed |

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security practitioners and vulnerability management analysts choosing or assessing operating systems and distributions

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (986 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are picking an offensive, forensic, or privacy distribution, you need to know what a security distribution is built on to patch it, or you are reducing attack surface with minimal and immutable operating systems

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Offensive and penetration-testing distributions](#offensive-and-penetration-testing-distributions), [Privacy and anonymity distributions](#privacy-and-anonymity-distributions), [Hardened, minimal, and enterprise distributions](#hardened-minimal-and-enterprise-distributions)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Linux Hardening Reference](LINUX_HARDENING_REFERENCE.md), [Windows Hardening Reference](WINDOWS_HARDENING_REFERENCE.md), [macOS Security Reference](MACOS_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How to read a security distribution

Four properties tell you how to assess and patch any distribution.

- Base: the upstream it derives from (Debian, Arch, Ubuntu, Red Hat, Gentoo, or a from-scratch build). The base sets the package format and most of the vulnerability exposure.
- Kernel: almost always Linux, but the hypervisor-based and BSD-based systems behave differently.
- Package manager: `apt` and `.deb` (Debian, Ubuntu), `dnf`/`rpm` (Red Hat family), `pacman` (Arch), `apk` (Alpine), `emerge` (Gentoo). This is how you inventory and patch.
- Update model: rolling release, fixed release, or image-based and immutable. Immutable systems are patched by replacing the image, not by updating packages in place.

## Offensive and penetration-testing distributions

Pre-loaded with offensive tooling. Treat them as sensitive endpoints, not disposable, since they hold engagement data and credentials.

- Kali Linux: the common penetration-testing distribution, built on Debian (tracking Debian testing), with `apt`. Rolling release.
- Parrot Security OS: Debian-based, with offensive and privacy tooling and a lighter footprint than Kali.
- BlackArch: Arch-based, a large tool repository layered on Arch with `pacman`. Rolling release, aimed at experienced users.
- Pentoo: Gentoo-based, source-compiled with `emerge`, offered as a live overlay.
- Commando VM and Flare-VM: not distributions but provisioning scripts that turn a Windows installation into an offensive workstation (Commando VM) or a malware-analysis workstation (Flare-VM). The base is Windows.

## Digital forensics and incident response

Built for acquisition and analysis, with write-blocking and analysis tooling.

- SIFT Workstation: Ubuntu-based, a forensics and incident-response toolkit from SANS.
- REMnux: Ubuntu-based, focused on reverse-engineering and malware analysis.
- CAINE: Ubuntu-based, a live forensics environment with a write-blocking default.
- Tsurugi Linux: a DFIR distribution with forensic and OSINT tooling.

## Defensive and monitoring systems

- Security Onion: a platform for network security monitoring, log management, and threat hunting that bundles Suricata, Zeek, and the Elastic stack. Recent versions are built on Oracle Linux; confirm the base for the version you deploy, since it has changed across releases.
- pfSense and OPNsense: firewall and router operating systems built on FreeBSD.

## Privacy and anonymity distributions

- Tails: Debian-based, amnesic (it leaves no trace on the host by running from removable media and routing traffic through Tor), for situations where leaving no local evidence matters.
- Whonix: Debian-based, split into a Tor gateway virtual machine and a workstation virtual machine so the workstation can only reach the network through Tor. It runs on Qubes, KVM, or a hypervisor.
- Qubes OS: not a conventional distribution but a security-by-compartmentalization operating system built on the Xen hypervisor, running activities in isolated virtual machines from Fedora and Debian templates so a compromise in one qube does not reach the others.

## Hardened, minimal, and enterprise distributions

These reduce attack surface in production, which is where they intersect vulnerability management: fewer packages mean fewer CVEs to patch.

- Red Hat Enterprise Linux (RHEL): the enterprise Red Hat distribution (upstream Fedora and CentOS Stream), with `dnf` and `rpm`, commonly hardened to CIS Benchmarks or DISA STIGs. Rebuilds include Rocky Linux and AlmaLinux. See [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md).
- Ubuntu and Ubuntu Pro: Debian-based, with Ubuntu Pro adding FIPS-validated cryptographic modules, kernel live patching, and extended security maintenance.
- SUSE Linux Enterprise: the enterprise SUSE distribution, with `zypper` and `rpm`.
- Alpine Linux: a minimal distribution built on `musl` libc and `busybox` with `apk`, common as a small container base.
- Chainguard and Wolfi: Wolfi is a minimal, container-focused base built for low vulnerability counts and frequent rebuilds; Chainguard Images are minimal, often distroless, images that aim to ship with few or zero known CVEs. Strong fit where image CVE counts drive remediation load.
- Flatcar Container Linux: a minimal, immutable, container-optimized operating system (the continuation of CoreOS Container Linux), updated by image rather than package.
- Bottlerocket: a minimal, image-based Linux from AWS for running containers, with much of the userland written in Rust and updates applied as signed images.
- Talos Linux: a minimal, immutable Kubernetes operating system managed entirely through an API, with no shell and no SSH, which removes a large class of interactive attack surface.

## General-purpose families and what they are built on

Most servers run one of a few families; knowing the lineage tells you the patch path.

- Debian: a from-the-project base; Ubuntu, Kali, Parrot, Tails, and Whonix all derive from it.
- Red Hat family: Fedora (leading edge), CentOS Stream (midstream), RHEL (enterprise), and the RHEL rebuilds Rocky and AlmaLinux.
- Arch and Gentoo: rolling and source-based bases behind BlackArch and Pentoo.
- FreeBSD: a BSD base behind pfSense, OPNsense, and TrueNAS.
- Windows Server: the Microsoft server base; hardened to CIS or STIG. See [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md).
- macOS: built on Darwin (the XNU kernel, combining Mach and BSD). See [macOS Security Reference](/MACOS_SECURITY_REFERENCE.md).

## Choosing and securing

- For offensive and forensic work, pick the distribution whose tooling fits the task, and secure it as a sensitive endpoint that holds client data.
- For production, prefer minimal and immutable systems where they fit, because a smaller package set is a smaller patch and CVE burden, which directly lowers vulnerability-management load.
- Whatever the base, harden to a published benchmark (CIS, DISA STIG) and patch on the base's own package path. See [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md) and [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Learning resources

- Each distribution publishes installation and security documentation; confirm the current base and release model there before you standardize on it.
- For hardening the resulting systems, see [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md), [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), and [macOS Security Reference](/MACOS_SECURITY_REFERENCE.md).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Platform hardening](/hubs/platform-hardening.md)
- [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md)
- [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md)
- [macOS Security Reference](/MACOS_SECURITY_REFERENCE.md)

<!-- related:end -->
