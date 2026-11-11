<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# openSUSE Tumbleweed

> The openSUSE community's continuously updated distribution, with frequent updates that carry new kernels, drivers, and desktop versions.

Part of [Operating systems](/operating-systems/README.md) (SUSE family). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Rolling | None | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Rolling release |

- Rolling: There are no numbered versions to reach end of life; staying current is the support model.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Rolling | Rolling (follows new upstream releases) | x86_64, aarch64, ppc64le, s390x | Independent (openSUSE) | Tumbleweed snapshots |

## Where its advisories live

- [openSUSE security updates (openSUSE-SU)](https://www.suse.com/support/update/): IDs take the form `openSUSE-SU-YYYY:NNNNN-N` (for example `openSUSE-SU-2026:12000-1`). Machine-readable: [CSAF 2.0](https://ftp.suse.com/pub/projects/security/csaf/), [OVAL](https://ftp.suse.com/pub/projects/security/oval/).

## How it patches

Package manager: `zypper` and `rpm`.

Tumbleweed moves forward as a whole: `zypper dup` (distribution upgrade) brings the system to the current snapshot.

```sh
sudo zypper refresh
sudo zypper dup
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -q kernel-default` | Installed default kernel packages |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| Rolling | `ID=opensuse-tumbleweed`, `VERSION_ID=<snapshot date>` | Not checked on a running system |

## Security relevance

openSUSE Tumbleweed is the rolling SUSE release, so it carries the newest kernel and packages with current mitigations and newly introduced bugs alike. As a host it presents the familiar Linux foothold surface of SSH, sudo, SUID, and kernel escalation, with the zypper supply chain and AppArmor on top. The rolling model means patch currency is continuous rather than release-bound.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss openSUSE Tumbleweed:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)

## On the Intelligence Hub

The library's vocabulary id for openSUSE Tumbleweed is `product:opensuse-tumbleweed`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Get openSUSE Tumbleweed](https://get.opensuse.org/tumbleweed/)
- [SUSE CSAF advisories](https://ftp.suse.com/pub/projects/security/csaf/)

<!-- os-pages:end -->
