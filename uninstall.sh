#!/bin/sh
# NetProbe IR universal Linux uninstaller
# SPDX-License-Identifier: GPL-3.0-only
set -eu

PURGE=0
ASSUME_YES=0
ROOTFS="/"
if [ -t 1 ] 2>/dev/null; then C_RESET='\033[0m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_BLUE='\033[34m'; else C_RESET=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_BLUE=''; fi
info(){ printf "%b[i]%b %s\n" "$C_BLUE" "$C_RESET" "$*"; }
ok(){ printf "%b[✓]%b %s\n" "$C_GREEN" "$C_RESET" "$*"; }
warn(){ printf "%b[!]%b %s\n" "$C_YELLOW" "$C_RESET" "$*"; }
die(){ printf "%b[x]%b %s\n" "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
usage(){ cat <<'USAGE'
NetProbe IR uninstaller

Usage: sudo ./uninstall.sh [options]
  --purge        Also permanently remove /etc/netprobe-ir and /var/lib/netprobe-ir
  --yes, -y      Confirm destructive --purge without prompting
  --root <path>  Operate below a staged root (testing/packaging)
  -h, --help     Show help

Without --purge, configuration, reports, incident evidence and PCAP data are preserved.
USAGE
}

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
  die "Run this uninstaller as root, or install sudo."
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --root) shift; [ "$#" -gt 0 ] || die "--root requires a path"; ROOTFS="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done
ROOTFS=${ROOTFS%/}; [ -n "$ROOTFS" ] || ROOTFS="/"

if [ "$PURGE" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ] && [ "$ROOTFS" = "/" ]; then
  if [ -t 0 ] 2>/dev/null; then
    printf "%bThis permanently deletes config, reports, incidents and PCAP evidence. Continue? [y/N] %b" "$C_YELLOW" "$C_RESET"
    read ans
    case "$ans" in y|Y|yes|YES|Yes) : ;; *) info "Purge cancelled."; exit 0 ;; esac
  else
    die "--purge in non-interactive mode requires --yes"
  fi
fi

info "Stopping and disabling service integration."
if [ "$ROOTFS" = "/" ]; then
  if command -v systemctl >/dev/null 2>&1; then systemctl disable --now netprobe-ir >/dev/null 2>&1 || true; fi
  if command -v rc-service >/dev/null 2>&1; then rc-service netprobe-ir stop >/dev/null 2>&1 || true; fi
  if command -v rc-update >/dev/null 2>&1; then rc-update del netprobe-ir default >/dev/null 2>&1 || true; fi
  if command -v sv >/dev/null 2>&1; then sv down netprobe-ir >/dev/null 2>&1 || true; fi
  if command -v service >/dev/null 2>&1; then service netprobe-ir stop >/dev/null 2>&1 || true; fi
  if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f netprobe-ir remove >/dev/null 2>&1 || true; fi
  if command -v chkconfig >/dev/null 2>&1; then chkconfig --del netprobe-ir >/dev/null 2>&1 || true; fi
fi
rm -f "$ROOTFS/etc/systemd/system/netprobe-ir.service" "$ROOTFS/usr/lib/systemd/system/netprobe-ir.service" "$ROOTFS/lib/systemd/system/netprobe-ir.service"
rm -f "$ROOTFS/etc/init.d/netprobe-ir" "$ROOTFS/etc/conf.d/netprobe-ir"
rm -rf "$ROOTFS/etc/sv/netprobe-ir"
rm -f "$ROOTFS/etc/service/netprobe-ir" "$ROOTFS/var/service/netprobe-ir"
if [ "$ROOTFS" = "/" ] && command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
ok "Service definitions removed."

info "Removing application files."
rm -f "$ROOTFS/usr/local/sbin/netprobe-ir" "$ROOTFS/usr/local/sbin/netprobe"
rm -rf "$ROOTFS/usr/local/share/doc/netprobe-ir"
ok "Binary and installed documentation removed."

if [ "$PURGE" -eq 1 ]; then
  rm -rf "$ROOTFS/etc/netprobe-ir" "$ROOTFS/var/lib/netprobe-ir"
  warn "Configuration and forensic data were permanently purged."
else
  [ -d "$ROOTFS/etc/netprobe-ir" ] && info "Preserved configuration: /etc/netprobe-ir"
  [ -d "$ROOTFS/var/lib/netprobe-ir" ] && info "Preserved forensic data: /var/lib/netprobe-ir"
fi
printf "\n%bNetProbe IR uninstallation complete.%b\n" "$C_GREEN" "$C_RESET"
