#!/data/data/com.termux/files/usr/bin/env bash
# odin-kali-full-install.sh
#
# Installs Kali Linux NetHunter (rootless) on an Ayn Android handheld and
# fills it with the full Kali toolset, including Wireshark configured for
# GUI use via Termux:X11.
#
# Usage (in Termux on the device):
#   curl -fsSL https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/claude/kali-linux-setup-DD0NL/scripts/odin-kali-full-install.sh -o setup.sh
#   bash setup.sh                 # default tier (~5 GB)
#   bash setup.sh --large         # ~15 GB
#   bash setup.sh --everything    # ~50+ GB, takes hours, may not fit
#   bash setup.sh --headless      # skip GUI/X11 setup
#
# Prereqs:
#   - Termux installed from F-Droid (NOT Play Store)
#   - For GUI: Termux:X11 app from F-Droid, plus a USB or BT keyboard
#   - Plenty of free storage (check with `df -h ~`)
#
# Capabilities & limits on Android handhelds:
#   - GUI tools (wireshark, burp, zaproxy, ghidra) work via Termux:X11
#   - Wireshark CAN capture from `lo` and proot-visible interfaces
#   - Wireshark CANNOT put internal Wi-Fi into monitor mode without a
#     custom NetHunter kernel (requires unlocked bootloader + root)
#   - Live Wi-Fi capture w/ injection: use a supported USB adapter
#     (RTL8812AU, MT7612U, AWUS036ACM, AWUS036NHA), and even then
#     you need kernel module support
#   - Metasploit, nmap, hashcat, john, sqlmap, gobuster, ffuf: all work
#   - Anything needing raw sockets on the host network: limited by Android
#
# Idempotent: rerunning upgrades and adds anything missing.

set -euo pipefail

TIER="default"
HEADLESS=0
for arg in "$@"; do
  case "$arg" in
    --everything|-e) TIER="everything" ;;
    --large|-l)      TIER="large" ;;
    --default|-d)    TIER="default" ;;
    --headless|-H)   HEADLESS=1 ;;
    -h|--help)
      sed -n '2,32p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[kali-full]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

ensure_termux() {
  [ -d "/data/data/com.termux" ] || die "This must run inside Termux on Android."
  log "Termux detected; updating base packages"
  yes | pkg update -y || true
  yes | pkg upgrade -y || true
  pkg install -y wget curl proot-distro tar pulseaudio
}

ensure_x11() {
  [ "$HEADLESS" -eq 1 ] && { log "Headless mode; skipping X11 setup"; return; }
  log "Installing Termux X11 stack (you also need the Termux:X11 app from F-Droid)"
  pkg install -y x11-repo
  pkg install -y termux-x11-nightly xorg-server-xvfb dbus
  cat > "$HOME/.start-x11.sh" <<'X11'
#!/data/data/com.termux/files/usr/bin/env bash
# Launch Termux:X11 server and a sound daemon. Open the Termux:X11 app to view.
pulseaudio --start --exit-idle-time=-1 --load="module-native-protocol-tcp auth-ip-acl=127.0.0.1 auth-anonymous=1" >/dev/null 2>&1 || true
export DISPLAY=:0
export PULSE_SERVER=127.0.0.1
termux-x11 :0 -ac &
sleep 1
echo "X11 server up on DISPLAY=:0"
X11
  chmod +x "$HOME/.start-x11.sh"
  log "X11 launcher written: ~/.start-x11.sh"
}

ensure_nethunter() {
  if ! command -v nethunter >/dev/null 2>&1; then
    log "Installing NetHunter rootless (this downloads ~1.5 GB)"
    pkg install -y wget
    wget -O "$HOME/install-nethunter.sh" https://offs.ec/2MceZWr
    chmod +x "$HOME/install-nethunter.sh"
    "$HOME/install-nethunter.sh"
  else
    log "NetHunter already installed"
  fi
}

inner_install() {
  local meta="kali-linux-$TIER"
  log "Will install metapackage: $meta"

  local inner="$HOME/.odin-kali-inner.sh"
  cat > "$inner" <<INNER
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export TERM=xterm-256color

echo "[inner] inside Kali chroot: \$(uname -m)"

apt-get update
apt-get install -y --no-install-recommends \\
  apt-transport-https ca-certificates curl gnupg2 dirmngr lsb-release \\
  software-properties-common locales tzdata

sed -i 's/^# *\\(en_US.UTF-8 UTF-8\\)/\\1/' /etc/locale.gen || true
locale-gen en_US.UTF-8 || true
update-locale LANG=en_US.UTF-8 || true

apt-get install -y kali-archive-keyring || true
apt-get update

echo "[inner] upgrading existing packages first"
apt-get full-upgrade -y

echo "[inner] installing $meta (this is the long part)"
apt-get install -y $meta

echo "[inner] installing Wireshark explicitly with capture caps"
apt-get install -y wireshark tshark dumpcap libcap2-bin
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap || true
groupadd -f wireshark
usermod -aG wireshark root || true

echo "[inner] extra QoL packages"
apt-get install -y \\
  tmux zsh git vim nano htop ripgrep fzf jq \\
  python3-pip pipx \\
  openssh-client mosh \\
  xfce4-terminal dbus-x11 \\
  fonts-dejavu fonts-noto-core || true

mkdir -p /root/.config
cat > /root/.bashrc-xenv <<'BENV'
export DISPLAY=:0
export PULSE_SERVER=127.0.0.1
export XDG_RUNTIME_DIR=/tmp/runtime-root
mkdir -p \$XDG_RUNTIME_DIR && chmod 700 \$XDG_RUNTIME_DIR
BENV
grep -q 'bashrc-xenv' /root/.bashrc || echo 'source /root/.bashrc-xenv' >> /root/.bashrc

apt-get clean
echo "[inner] done. Disk usage:"
df -h / || true
INNER
  chmod +x "$inner"

  log "Running installer inside Kali (this will take a while; do not let the device sleep)"
  termux-wake-lock || true
  nethunter -r bash "$inner"
  termux-wake-unlock || true
}

write_launchers() {
  log "Writing convenience launchers in \$HOME"
  cat > "$HOME/kali-gui.sh" <<'L1'
#!/data/data/com.termux/files/usr/bin/env bash
# Boots X11 then drops you into Kali with DISPLAY ready.
bash ~/.start-x11.sh
exec nethunter
L1
  chmod +x "$HOME/kali-gui.sh"

  cat > "$HOME/kali-wireshark.sh" <<'L2'
#!/data/data/com.termux/files/usr/bin/env bash
# Launch Wireshark GUI on the Termux:X11 display.
bash ~/.start-x11.sh
nethunter -r bash -lc 'source /root/.bashrc-xenv && wireshark &'
L2
  chmod +x "$HOME/kali-wireshark.sh"
}

main() {
  log "Tier: $TIER  Headless: $HEADLESS"
  ensure_termux
  ensure_x11
  ensure_nethunter
  inner_install
  write_launchers

  log "All done."
  log ""
  log "Next steps:"
  log "  1. Open the Termux:X11 app once and grant any prompts."
  log "  2. Run:  ~/kali-gui.sh           # launches Kali shell with GUI ready"
  log "  3. Run:  ~/kali-wireshark.sh     # opens Wireshark on the X11 display"
  log ""
  log "Reality check on Wireshark:"
  log "  * Reading pcap files: works."
  log "  * Capturing on 'lo' inside the proot: works."
  log "  * Capturing on the device's real Wi-Fi (wlan0): NOT possible without"
  log "    an unlocked bootloader, custom NetHunter kernel, and root."
  log "  * For real Wi-Fi capture/injection plug in a supported USB adapter"
  log "    (RTL8812AU / MT7612U / AWUS036ACM) and check 'iw dev' inside Kali."
}

main "$@"
