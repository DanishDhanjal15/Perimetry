#!/bin/bash
# Removes what install.sh installs: the payload at /opt/perimetry and the
# launcher at /usr/local/bin/perimetry. Run with sudo.
set -euo pipefail

INSTALL_DIR="/opt/perimetry"
BIN_PATH="/usr/local/bin/perimetry"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[!] Please run as root:  sudo ./uninstall-perimetry.sh"
  exit 1
fi

echo "[*] Removing launcher: $BIN_PATH"
rm -f "$BIN_PATH"

echo "[*] Removing payload:  $INSTALL_DIR"
rm -rf "$INSTALL_DIR"

echo "[✓] Perimetry uninstalled."
echo "    If you instead installed with pip, remove it with:  pip uninstall perimetry"
