#!/bin/sh
# NetProbe IR universal Linux installer
# SPDX-License-Identifier: GPL-3.0-only
set -eu

APP_ID="netprobe-ir"
REPO="https://github.com/cumakurt/netprobe-ir"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || printf '%s' '1.0.0')
ROOTFS="/"
NO_START=0
NO_ENABLE=0
FORCE_CONFIG=0
SOURCE_MODE="auto"
TMPDIR_INSTALL=""
LOGFILE=""
STEP_NO=0
STEP_TOTAL=8

if [ -t 1 ] 2>/dev/null; then
  C_RESET='\033[0m'; C_BLUE='\033[34m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_BOLD='\033[1m'
else
  C_RESET=''; C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_BOLD=''
fi

info() { printf "%b[i]%b %s\n" "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf "%b[✓]%b %s\n" "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_RESET" "$*"; }
die()  {
  printf "%b[x]%b %s\n" "$C_RED" "$C_RESET" "$*" >&2
  if [ -n "$LOGFILE" ] && [ -s "$LOGFILE" ]; then
    printf '\nLast installer log lines:\n' >&2
    tail -n 25 "$LOGFILE" >&2 2>/dev/null || true
  fi
  exit 1
}
step() { STEP_NO=$((STEP_NO + 1)); printf "\n%b[%d/%d]%b %s\n" "$C_BOLD" "$STEP_NO" "$STEP_TOTAL" "$C_RESET" "$*"; }
usage() {
  cat <<USAGE
NetProbe IR installer v${VERSION}

Usage: sudo ./install.sh [options]

Options:
  --yes, -y          Reserved for unattended package-manager operations
  --no-start         Install but do not start the service
  --no-enable        Do not enable service at boot
  --force-config     Replace existing config.json after creating a timestamped backup
  --bundled-only     Never download a missing binary
  --download-only    Ignore bundled binary and download release v${VERSION}
  --root <path>      Stage files below another root (testing/packaging; no service start)
  -h, --help         Show this help

NetProbe IR is shipped as a fully static binary and normally needs no runtime
packages. If the matching bundled binary is missing, the installer can detect
common Linux package managers, install a minimal HTTPS downloader if needed,
and retrieve the release from ${REPO}.
USAGE
}

# Staged-root installs can run without privilege when the staging directory is writable.
NEEDS_ROOT=1
EXPECT_ROOT_ARG=0
for ARG in "$@"; do
  if [ "$EXPECT_ROOT_ARG" -eq 1 ]; then NEEDS_ROOT=0; EXPECT_ROOT_ARG=0; continue; fi
  [ "$ARG" = "--root" ] && EXPECT_ROOT_ARG=1
done
if [ "$(id -u)" -ne 0 ] && [ "$NEEDS_ROOT" -eq 1 ]; then
  if command -v sudo >/dev/null 2>&1; then
    info "Administrative privileges are required; continuing with sudo."
    exec sudo -- "$0" "$@"
  fi
  die "Run this installer as root, or install sudo."
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes|-y) : ;;
    --no-start) NO_START=1 ;;
    --no-enable) NO_ENABLE=1 ;;
    --force-config) FORCE_CONFIG=1 ;;
    --bundled-only) SOURCE_MODE="bundled" ;;
    --download-only) SOURCE_MODE="download" ;;
    --root)
      shift
      [ "$#" -gt 0 ] || die "--root requires a path"
      ROOTFS="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

ROOTFS=${ROOTFS%/}
[ -n "$ROOTFS" ] || ROOTFS="/"
if [ "$ROOTFS" != "/" ]; then
  mkdir -p "$ROOTFS"
  NO_START=1
  NO_ENABLE=1
fi

cleanup() { [ -n "$TMPDIR_INSTALL" ] && [ -d "$TMPDIR_INSTALL" ] && rm -rf "$TMPDIR_INSTALL" || true; }
trap cleanup EXIT HUP INT TERM
TMPDIR_INSTALL=$(mktemp -d 2>/dev/null || mktemp -d -t netprobe-ir-install)
LOGFILE="$TMPDIR_INSTALL/install.log"
run_quiet() { "$@" >>"$LOGFILE" 2>&1; }

step "Inspecting operating system and architecture"
[ "$(uname -s)" = "Linux" ] || die "NetProbe IR currently supports Linux only."
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Unsupported CPU architecture: $ARCH_RAW. Prebuilt packages currently include amd64 and arm64." ;;
esac
DISTRO_NAME="Linux"
DISTRO_ID="unknown"
if [ -r /etc/os-release ]; then
  # PRETTY_NAME and ID are supplied by the operating system.
  . /etc/os-release
  DISTRO_NAME=${PRETTY_NAME:-${NAME:-Linux}}
  DISTRO_ID=${ID:-unknown}
fi
ok "$DISTRO_NAME · architecture $ARCH"

step "Checking runtime and installer requirements"
for cmd in uname id mkdir cp mv chmod chown ln rm grep awk sed install date tail mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required base command '$cmd' was not found. Install your distribution's base/core utilities package."
done
HASH_TOOL=""
if command -v sha256sum >/dev/null 2>&1; then HASH_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then HASH_TOOL="shasum"
fi
if [ -n "$HASH_TOOL" ]; then
  ok "Static binary requires no runtime libraries; SHA-256 verification is available."
else
  warn "No SHA-256 utility found. NetProbe IR itself can run, but local artifact checksum verification is unavailable."
fi

pkg_manager() {
  for pm in apt-get dnf yum zypper pacman apk xbps-install emerge eopkg; do
    if command -v "$pm" >/dev/null 2>&1; then printf '%s\n' "$pm"; return 0; fi
  done
  return 1
}
install_download_dependency() {
  PM=$(pkg_manager || true)
  [ -n "$PM" ] || die "Neither curl nor wget is installed and no supported package manager was detected. Install curl or wget and re-run."
  info "HTTPS downloader is missing; installing the minimal dependency via $PM."
  case "$PM" in
    apt-get) run_quiet apt-get update -qq && run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl ;;
    dnf) run_quiet dnf -q -y install ca-certificates curl ;;
    yum) run_quiet yum -q -y install ca-certificates curl ;;
    zypper) run_quiet zypper --non-interactive --quiet install ca-certificates curl ;;
    pacman) run_quiet pacman -Sy --noconfirm --needed ca-certificates curl ;;
    apk) run_quiet apk add --no-progress ca-certificates curl ;;
    xbps-install) run_quiet xbps-install -Sy ca-certificates curl ;;
    emerge) run_quiet emerge --quiet net-misc/curl app-misc/ca-certificates ;;
    eopkg) run_quiet eopkg install -y curl ca-certs ;;
    *) return 1 ;;
  esac || die "Failed to install download support with $PM."
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "Downloader installation completed without providing curl/wget."
  ok "HTTPS downloader is ready."
}
download() {
  URL=$1
  OUT=$2
  if command -v curl >/dev/null 2>&1; then
    run_quiet curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$OUT" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    run_quiet wget -q --https-only --timeout=30 --tries=3 -O "$OUT" "$URL"
  else
    install_download_dependency
    download "$URL" "$OUT"
  fi
}
hash_file() {
  if [ "$HASH_TOOL" = "sha256sum" ]; then sha256sum "$1" | awk '{print $1}'
  elif [ "$HASH_TOOL" = "shasum" ]; then shasum -a 256 "$1" | awk '{print $1}'
  else return 1
  fi
}

step "Selecting and verifying the NetProbe IR binary"
BUNDLED="$SCRIPT_DIR/dist/netprobe-linux-$ARCH"
SELECTED=""
if [ "$SOURCE_MODE" != "download" ] && [ -f "$BUNDLED" ]; then
  SELECTED="$BUNDLED"
  info "Using bundled static $ARCH binary."
elif [ "$SOURCE_MODE" = "bundled" ]; then
  die "Bundled binary not found: $BUNDLED"
else
  ASSET="netprobe-linux-$ARCH"
  RELEASE_BASE="$REPO/releases/download/v$VERSION"
  SELECTED="$TMPDIR_INSTALL/$ASSET"
  info "Bundled binary is unavailable; downloading release v$VERSION."
  download "$RELEASE_BASE/$ASSET" "$SELECTED" || die "Could not download release asset $ASSET."
  chmod 0755 "$SELECTED"
  if download "$RELEASE_BASE/SHA256SUMS" "$TMPDIR_INSTALL/SHA256SUMS"; then
    EXPECTED=$(awk -v n="dist/$ASSET" -v b="$ASSET" '$2==n || $2==b || $2=="*"b {print $1; exit}' "$TMPDIR_INSTALL/SHA256SUMS")
    if [ -n "$EXPECTED" ] && [ -n "$HASH_TOOL" ]; then
      ACTUAL=$(hash_file "$SELECTED")
      [ "$ACTUAL" = "$EXPECTED" ] || die "Downloaded binary SHA-256 mismatch."
      ok "Downloaded release checksum verified."
    else
      warn "Release checksum file had no usable entry; HTTPS download succeeded but SHA-256 could not be independently checked."
    fi
  else
    warn "Release checksum could not be downloaded; continuing with HTTPS transport protection only."
  fi
fi

if [ "$SELECTED" = "$BUNDLED" ] && [ -n "$HASH_TOOL" ] && [ -f "$SCRIPT_DIR/dist/SHA256SUMS" ]; then
  EXPECTED=$(awk -v n="dist/netprobe-linux-$ARCH" '$2==n {print $1; exit}' "$SCRIPT_DIR/dist/SHA256SUMS")
  if [ -n "$EXPECTED" ]; then
    ACTUAL=$(hash_file "$SELECTED")
    [ "$ACTUAL" = "$EXPECTED" ] || die "Bundled binary SHA-256 mismatch; refusing to install a modified/corrupt artifact."
    ok "Bundled binary checksum verified."
  else
    warn "No checksum entry exists for the bundled $ARCH binary."
  fi
fi
[ -x "$SELECTED" ] || chmod 0755 "$SELECTED"

step "Installing binary, configuration and data directories"
BIN_DIR="$ROOTFS/usr/local/sbin"
CONFIG_DIR="$ROOTFS/etc/netprobe-ir"
DATA_DIR="$ROOTFS/var/lib/netprobe-ir"
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 0755 "$BIN_DIR"
chmod 0750 "$CONFIG_DIR" "$DATA_DIR"
install -m 0755 "$SELECTED" "$BIN_DIR/netprobe-ir"
ln -sfn netprobe-ir "$BIN_DIR/netprobe"
if [ -f "$CONFIG_DIR/config.json" ]; then
  if [ "$FORCE_CONFIG" -eq 1 ]; then
    cp -p "$CONFIG_DIR/config.json" "$CONFIG_DIR/config.json.bak.$(date +%Y%m%d%H%M%S)"
    install -m 0640 "$SCRIPT_DIR/configs/netprobe.example.json" "$CONFIG_DIR/config.json"
    warn "Existing configuration was backed up and replaced."
  else
    info "Keeping existing /etc/netprobe-ir/config.json"
  fi
else
  install -m 0640 "$SCRIPT_DIR/configs/netprobe.example.json" "$CONFIG_DIR/config.json"
fi
chown root:root "$CONFIG_DIR" "$DATA_DIR" "$BIN_DIR/netprobe-ir" 2>/dev/null || true
[ ! -f "$CONFIG_DIR/config.json" ] || chown root:root "$CONFIG_DIR/config.json" 2>/dev/null || true
ok "Program, configuration and persistent data paths are ready."

step "Bootstrapping secure web administrator"
BOOTSTRAP_OUTPUT=""
if [ -f "$DATA_DIR/auth/users.json" ]; then
  info "Authentication store already exists; bootstrap credentials will not be changed."
else
  if BOOTSTRAP_OUTPUT=$($BIN_DIR/netprobe-ir auth bootstrap --data-dir "$DATA_DIR" --username admin 2>&1); then
    chmod 0700 "$DATA_DIR/auth" 2>/dev/null || true
    chmod 0600 "$DATA_DIR/auth/users.json" 2>/dev/null || true
    ok "Initial administrator was created. Credentials will be displayed once at the end of installation."
  else
    die "Administrator bootstrap failed: $BOOTSTRAP_OUTPUT"
  fi
fi

step "Installing documentation and GNU GPLv3 license"
DOC_DIR="$ROOTFS/usr/local/share/doc/netprobe-ir"
mkdir -p "$DOC_DIR"
for f in README.md README_TR.md LICENSE AUTHORS COPYRIGHT CHANGELOG.md TEST-RESULTS.md; do
  if [ -f "$SCRIPT_DIR/$f" ]; then install -m 0644 "$SCRIPT_DIR/$f" "$DOC_DIR/$f"; fi
done
if [ -d "$SCRIPT_DIR/docs" ]; then
  mkdir -p "$DOC_DIR/docs"
  for f in "$SCRIPT_DIR"/docs/*.md; do
    [ -f "$f" ] && install -m 0644 "$f" "$DOC_DIR/docs/$(basename "$f")"
  done
fi
mkdir -p "$DOC_DIR/examples"
for f in netprobe.example.json iocs.example.json ids-rules.example.json stix-bundle.example.json syslog-destinations.example.json flow-collectors.example.json detections.example.npdl yara-rules.example.yar kev-catalog.example.json sigma-rule.example.yml sigma-correlation.example.yml suricata-rules.example.rules enrichment.example.json playbooks.example.json; do
  [ -f "$SCRIPT_DIR/configs/$f" ] && install -m 0644 "$SCRIPT_DIR/configs/$f" "$DOC_DIR/examples/$f"
done
ok "Documentation, IDS/IOC/STIX/export/NPDL/YARA-X/KEV examples, developer metadata and license installed."

step "Detecting init system and installing service integration"
INIT="none"
if [ "$ROOTFS" != "/" ]; then
  # Staging mode uses host capability only to choose a representative service layout.
  if command -v systemctl >/dev/null 2>&1; then INIT="systemd"
  elif command -v rc-service >/dev/null 2>&1; then INIT="openrc"
  elif command -v sv >/dev/null 2>&1; then INIT="runit"
  else INIT="sysv"
  fi
elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then INIT="systemd"
elif command -v rc-service >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then INIT="openrc"
elif command -v sv >/dev/null 2>&1; then INIT="runit"
elif command -v service >/dev/null 2>&1 || [ -d /etc/init.d ]; then INIT="sysv"
fi

case "$INIT" in
  systemd)
    mkdir -p "$ROOTFS/etc/systemd/system"
    install -m 0644 "$SCRIPT_DIR/packaging/systemd/netprobe-ir.service" "$ROOTFS/etc/systemd/system/netprobe-ir.service"
    if [ "$ROOTFS" = "/" ]; then run_quiet systemctl daemon-reload || die "systemd daemon-reload failed."; fi
    ok "systemd service installed."
    ;;
  openrc)
    mkdir -p "$ROOTFS/etc/init.d" "$ROOTFS/etc/conf.d"
    install -m 0755 "$SCRIPT_DIR/packaging/openrc/netprobe-ir" "$ROOTFS/etc/init.d/netprobe-ir"
    install -m 0644 "$SCRIPT_DIR/packaging/openrc/netprobe-ir.conf" "$ROOTFS/etc/conf.d/netprobe-ir"
    ok "OpenRC service installed."
    ;;
  runit)
    mkdir -p "$ROOTFS/etc/sv/netprobe-ir"
    install -m 0755 "$SCRIPT_DIR/packaging/runit/run" "$ROOTFS/etc/sv/netprobe-ir/run"
    if [ -d "$ROOTFS/etc/service" ]; then ln -sfn /etc/sv/netprobe-ir "$ROOTFS/etc/service/netprobe-ir"
    elif [ -d "$ROOTFS/var/service" ]; then ln -sfn /etc/sv/netprobe-ir "$ROOTFS/var/service/netprobe-ir"
    fi
    ok "runit service installed."
    ;;
  sysv)
    mkdir -p "$ROOTFS/etc/init.d"
    install -m 0755 "$SCRIPT_DIR/packaging/sysv/netprobe-ir" "$ROOTFS/etc/init.d/netprobe-ir"
    ok "SysV init script installed."
    ;;
  *) warn "No supported init system detected. Binary/config installation is complete; start NetProbe IR manually." ;;
esac

step "Enabling and starting the service"
if [ "$ROOTFS" != "/" ]; then
  info "Staged-root mode: service enable/start intentionally skipped."
elif [ "$INIT" = "none" ]; then
  info "No init integration is available; use the manual start command documented in README."
else
  if [ "$NO_ENABLE" -eq 0 ]; then
    case "$INIT" in
      systemd) run_quiet systemctl enable netprobe-ir || warn "systemd service could not be enabled automatically." ;;
      openrc) run_quiet rc-update add netprobe-ir default || warn "OpenRC service could not be enabled automatically." ;;
      runit) : ;;
      sysv)
        if command -v update-rc.d >/dev/null 2>&1; then run_quiet update-rc.d netprobe-ir defaults || warn "SysV boot registration failed."
        elif command -v chkconfig >/dev/null 2>&1; then run_quiet chkconfig --add netprobe-ir || warn "SysV chkconfig registration failed."
        fi
        ;;
    esac
  fi
  if [ "$NO_START" -eq 0 ]; then
    case "$INIT" in
      systemd) run_quiet systemctl restart netprobe-ir || warn "Service is installed but systemd could not start it." ;;
      openrc) run_quiet rc-service netprobe-ir restart || run_quiet rc-service netprobe-ir start || warn "Service is installed but OpenRC could not start it." ;;
      runit) command -v sv >/dev/null 2>&1 && run_quiet sv up netprobe-ir || true ;;
      sysv) run_quiet service netprobe-ir restart || run_quiet /etc/init.d/netprobe-ir start || warn "Service is installed but SysV could not start it." ;;
    esac
  fi
  ok "Service integration completed ($INIT)."
fi

step "Running post-install verification"
INSTALLED_BIN="$BIN_DIR/netprobe-ir"
if [ "$ROOTFS" = "/" ]; then
  if "$INSTALLED_BIN" --self-test >>"$LOGFILE" 2>&1; then ok "Embedded functional self-test passed."
  else die "Installed binary self-test failed."
  fi
  VERSION_LINE=$($INSTALLED_BIN --version 2>/dev/null || true)
  [ -n "$VERSION_LINE" ] && info "$VERSION_LINE"
  # Advanced v0.7 integrations are optional capabilities; report rather than
  # silently pretending they are embedded in the static sensor binary.
  command -v yr >/dev/null 2>&1 && info "Optional capability: YARA-X runtime detected (yr)." || info "Optional capability: YARA-X runtime not installed; file hashing/reconstruction still works."
  command -v wasmtime >/dev/null 2>&1 && info "Optional capability: wasmtime detected for WASI plugins." || info "Optional capability: wasmtime not installed; WASM plugins remain disabled/unavailable."
  command -v kcat >/dev/null 2>&1 && info "Optional capability: kcat detected for Kafka streaming." || info "Optional capability: kcat not installed; Kafka adapter remains unavailable until installed."
  command -v bpftrace >/dev/null 2>&1 && info "Optional capability: bpftrace detected for eBPF attribution." || info "Optional capability: bpftrace not installed; process attribution uses /proc fallback."
  if [ "$INIT" = "systemd" ] && [ "$NO_START" -eq 0 ]; then
    if systemctl is-active --quiet netprobe-ir; then ok "netprobe-ir.service is active."
    else warn "netprobe-ir.service is not active; inspect: journalctl -u netprobe-ir"
    fi
  fi
else
  [ -x "$INSTALLED_BIN" ] || die "Staged binary is not executable."
  ok "Staged installation layout verified."
fi

printf "\n%bInstallation complete.%b\n" "$C_GREEN$C_BOLD" "$C_RESET"
printf '%s\n' '  Binary : /usr/local/sbin/netprobe-ir' '  Alias  : /usr/local/sbin/netprobe' '  Config : /etc/netprobe-ir/config.json' '  Data   : /var/lib/netprobe-ir' '  Web UI : http://127.0.0.1:8443' '  About  : netprobe-ir --about'
if [ "$INIT" = "systemd" ]; then printf '%s\n' '  Logs   : journalctl -u netprobe-ir -f'; fi
if [ -n "$BOOTSTRAP_OUTPUT" ] && printf '%s' "$BOOTSTRAP_OUTPUT" | grep -q 'Initial password:'; then
  printf '\n%bInitial Web Administrator%b\n%s\n' "$C_YELLOW$C_BOLD" "$C_RESET" "$BOOTSTRAP_OUTPUT"
  printf '%s\n' 'IMPORTANT: This password is shown once. Sign in and change it immediately.' 'Recovery: netprobe-ir auth reset --data-dir /var/lib/netprobe-ir --username admin'
fi
printf '\nDeveloper: Cuma KURT <cumakurt@gmail.com>\nLinkedIn : https://www.linkedin.com/in/cuma-kurt-34414917/\nRepository: %s\n' "$REPO"
