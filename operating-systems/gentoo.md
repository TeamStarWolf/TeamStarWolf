<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Gentoo Linux

> A source-based distribution: Portage, its software distribution system, builds packages to the options each system sets; there is no installation program, and the Gentoo Handbook guides the install.

Part of [Operating systems](/operating-systems/README.md) (Independent distributions). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Rolling | None | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Rolling release |

- Rolling: There are no numbered versions to reach end of life; staying current is the support model.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Rolling | Chosen and built by the administrator | amd64, x86, arm64, arm, ppc, riscv, s390, alpha, hppa, loong, m68k, mips, sparc | Independent | Gentoo ebuild repository |

## Where its advisories live

- [Gentoo Linux Security Advisories (GLSA)](https://security.gentoo.org/glsa): IDs take the form `GLSA YYYYMM-NN` (for example `GLSA 202610-02`). Machine-readable: [RSS](https://security.gentoo.org/glsa/feed.rss).

## How it patches

Package manager: Portage (`emerge`).

The administrator chooses and builds the kernel, so there is no single distribution kernel version.

```sh
sudo emerge --sync
sudo emerge --ask --update --deep --newuse @world
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `cat /etc/gentoo-release` | Base system release string |
| `uname -r` | Release of the running kernel |
| `eselect kernel list` | Installed kernel source trees and the selected one |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| Rolling | `ID=gentoo` | Not checked on a running system |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Gentoo Linux is `product:gentoo-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Gentoo downloads](https://www.gentoo.org/downloads/)
- [About Gentoo](https://www.gentoo.org/get-started/about/)
- [Gentoo get started](https://www.gentoo.org/get-started/)
- [Gentoo Linux Security Advisories](https://security.gentoo.org/glsa)

<!-- os-pages:end -->
