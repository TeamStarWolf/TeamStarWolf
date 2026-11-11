<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Fedora

> The Fedora Project's community distribution, with a new release about every six months; Red Hat Enterprise Linux 8 was based on Fedora 28.

Part of [Operating systems](/operating-systems/README.md) (Red Hat Enterprise Linux family). Support dates come from the [endoflife.date](https://endoflife.date/fedora) API (`https://endoflife.date/api/fedora.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 45 | None | 2026-11-03 | 45 | Not published | 2027-12-08 | Not published | Supported |
| 44 | None | 2026-04-28 | 44 | Not published | 2027-06-02 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 45 | Rebased during the release | x86_64, aarch64 | Independent (Fedora Project) | Fedora updates repository |
| 44 | Rebased during the release | x86_64, aarch64 | Independent (Fedora Project) | Fedora updates repository |

## Where its advisories live

- [Fedora updates (Bodhi), security type](https://bodhi.fedoraproject.org/updates/?type=security): IDs take the form `FEDORA-YYYY-xxxxxxxxxx` (for example `FEDORA-2026-981a830ea5`). Machine-readable: [RSS](https://bodhi.fedoraproject.org/rss/updates/?type=security).

## How it patches

Package manager: `dnf` and `rpm`.

The kernel is rebased to newer upstream stable releases during a release's life (Fedora wiki, Kernel rebases), so the kernel column says rebased rather than naming one series.

```sh
sudo dnf upgrade --refresh
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `cat /etc/fedora-release` | Release name and number |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -q kernel` | Installed kernel packages; more than one means a reboot may be pending |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 45 | `ID=fedora`, `VERSION_ID=45` | Not checked on a running system |
| 44 | `ID=fedora`, `VERSION_ID=44` | Not checked on a running system |

## Security relevance

Fedora is a fast-moving workstation and developer host that previews what later lands in RHEL, so it runs newer kernels and packages with both current mitigations and freshly introduced bugs. As a host it presents the standard Linux foothold surface of SSH, sudo, SUID, and kernel escalation, with the dnf supply chain on top. SELinux is enforcing by default, which blunts several post-exploitation moves; the hardening references below cover the baseline.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Fedora:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)

## On the Intelligence Hub

The library's vocabulary id for Fedora is `product:fedora`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Fedora architectures](https://fedoraproject.org/wiki/Architectures)
- [Fedora kernel rebases](https://fedoraproject.org/wiki/KernelRebases)
- [Fedora security updates (Bodhi RSS)](https://bodhi.fedoraproject.org/rss/updates/?type=security)

<!-- os-pages:end -->
