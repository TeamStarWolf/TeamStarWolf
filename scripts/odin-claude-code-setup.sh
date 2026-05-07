#!/data/data/com.termux/files/usr/bin/env bash
# odin-claude-code-setup.sh
#
# One-shot installer for Claude Code on an Ayn Odin running Termux.
# Optionally installs into the Kali NetHunter proot instead of bare Termux.
#
# Usage (in Termux on the Odin):
#   curl -fsSL <raw-url>/scripts/odin-claude-code-setup.sh -o setup.sh
#   bash setup.sh                # install in Termux
#   bash setup.sh --nethunter    # install inside Kali NetHunter chroot
#
# Prereqs:
#   - Termux from F-Droid (NOT Play Store)
#   - For --nethunter: NetHunter rootless already installed (`nethunter` command works)
#
# This script is idempotent; rerunning it upgrades Claude Code to the latest version.

set -euo pipefail

MODE="termux"
if [[ "${1:-}" == "--nethunter" || "${1:-}" == "-n" ]]; then
  MODE="nethunter"
fi

log()  { printf '\033[1;36m[odin-setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

install_in_termux() {
  log "Updating Termux packages"
  pkg update -y && pkg upgrade -y

  log "Installing nodejs, git, and helpers"
  pkg install -y nodejs git ripgrep openssh termux-api

  log "Configuring user-local npm prefix (avoids root-write issues)"
  mkdir -p "$HOME/.npm-global"
  npm config set prefix "$HOME/.npm-global"
  if ! grep -q 'NPM_GLOBAL' "$HOME/.bashrc" 2>/dev/null; then
    {
      echo ''
      echo '# NPM_GLOBAL'
      echo 'export PATH="$HOME/.npm-global/bin:$PATH"'
    } >> "$HOME/.bashrc"
  fi
  export PATH="$HOME/.npm-global/bin:$PATH"

  log "Installing @anthropic-ai/claude-code"
  npm install -g @anthropic-ai/claude-code

  log "Granting Termux storage access (you will see an Android permission prompt)"
  termux-setup-storage || warn "termux-setup-storage skipped or denied"

  log "Acquiring wakelock so long sessions are not killed by Android"
  termux-wake-lock || true
}

install_in_nethunter() {
  command -v nethunter >/dev/null 2>&1 || die "NetHunter not found. Install it first: https://www.kali.org/docs/nethunter/installing-nethunter-termux/"

  log "Writing inner installer to be run inside Kali"
  local inner="$HOME/.odin-claude-inner.sh"
  cat > "$inner" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y nodejs npm git ripgrep curl ca-certificates
mkdir -p /root/.npm-global
npm config set prefix /root/.npm-global
grep -q 'npm-global' /root/.bashrc 2>/dev/null || echo 'export PATH="/root/.npm-global/bin:$PATH"' >> /root/.bashrc
export PATH="/root/.npm-global/bin:$PATH"
npm install -g @anthropic-ai/claude-code
echo "[inner] claude installed: $(command -v claude || echo MISSING)"
INNER
  chmod +x "$inner"

  log "Executing installer inside Kali NetHunter chroot"
  nethunter -r bash "$inner"

  log "To launch Claude Code later: 'nethunter' then 'claude'"
}

main() {
  log "Mode: $MODE"
  case "$MODE" in
    termux)    install_in_termux ;;
    nethunter) install_in_nethunter ;;
    *)         die "Unknown mode: $MODE" ;;
  esac

  log "Done. Verify with:  claude --version"
  log "First run will open a browser to authenticate, or accept an API key."
  log ""
  log "Recommended next steps on the Odin:"
  log "  - Pair a Bluetooth keyboard (terminal UX is rough without one)"
  log "  - 'pkg install tmux' and learn 2-3 keybinds for split panes"
  log "  - Settings -> Apps -> Termux -> Battery -> Unrestricted"
  log "  - Install 'Hacker's Keyboard' from F-Droid for on-screen Ctrl/Esc/Tab"
}

main "$@"
