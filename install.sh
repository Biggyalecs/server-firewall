#!/bin/sh
###############################################################################
# Copyright 2006-2025, LinuxShield
# URL: http://www.linuxshield.net
# Email: firewall@linuxshield.net
###############################################################################
set -euo pipefail

track_install() {
	
	if [[ "${LS_DISABLE_TELEMETRY:-0}" =~ ^(1|true|yes)$ ]]; then
    	return 0
  	fi
  	if [[ -f /etc/linuxshield/telemetry.disabled ]] || [[ "$(tr -d ' \t\r\n' < /etc/linuxshield/telemetry 2>/dev/null)" == "disabled" ]]; then
    	return 0
  	fi
  local panel="$1"                             # ex: cpanel, directadmin, generic
  local endpoint="https://download.linuxshield.net/stats/install.php"

  # ID anonim (preferă /etc/machine-id; fallback hostname). Hash SHA256.
  local raw_id=""
  if [[ -r /etc/machine-id ]]; then
    raw_id="$(cat /etc/machine-id)"
  else
    raw_id="$(hostname -f 2>/dev/null || hostname)"
  fi
  local anon_id
  anon_id="$(printf '%s' "$raw_id" | sha256sum | awk '{print $1}')"

  # Versiuni panou (dacă există)
  local panel_ver=""
  case "$panel" in
    cpanel)      [[ -r /usr/local/cpanel/version ]] && panel_ver="$(cat /usr/local/cpanel/version)";;
    directadmin) [[ -x /usr/local/directadmin/directadmin ]] && panel_ver="$(/usr/local/directadmin/directadmin v 2>/dev/null | head -n1)";;
    interworx)   [[ -x /usr/local/interworx/bin/iworx ]] && panel_ver="$(/usr/local/interworx/bin/iworx -v 2>/dev/null)";;
    cwp)         panel_ver="CWP";;
    vesta)       panel_ver="Vesta";;
    cyberpanel)  [[ -r /usr/local/CyberCP/version.txt ]] && panel_ver="$(cat /usr/local/CyberCP/version.txt)";;
    *)           panel_ver="";;
  esac

  # OS/Kernel 
  local os="$(uname -s)"
  local kernel="$(uname -r)"
  local arch="$(uname -m)"

  # Payload
  local data="id=${anon_id}&panel=${panel}&panel_ver=$(printf '%s' "$panel_ver" | tr -d '\n' | sed 's/[&]/_/g')&os=${os}&kernel=${kernel}&arch=${arch}&installer_ver=1"

  # Send in backgrounds stats about the installs
  if command -v curl >/dev/null 2>&1; then
    nohup bash -c "curl -fsS -m 3 -o /dev/null -A 'LinuxShield-Installer' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data '${data}' '${endpoint}' || true" >/dev/null 2>&1 &
  elif command -v wget >/dev/null 2>&1; then
    nohup bash -c "wget -q -T 3 --header='Content-Type: application/x-www-form-urlencoded' \
      --post-data='${data}' -O /dev/null '${endpoint}' || true" >/dev/null 2>&1 &
  fi
}

echo
echo "Selecting installer..."
echo

if [ -e "/usr/local/cpanel/version" ]; then
	echo "Running csf cPanel installer"
	 track_install "cpanel"
	echo
	sh install.cpanel.sh
elif [ -e "/usr/local/directadmin/directadmin" ]; then
	echo "Running csf DirectAdmin installer"
	track_install "directadmin"
	echo
	sh install.directadmin.sh
elif [ -e "/usr/local/interworx" ]; then
	echo "Running csf InterWorx installer"
	track_install "interworx"
	echo
	sh install.interworx.sh
elif [ -e "/usr/local/cwpsrv" ]; then
	echo "Running csf CentOS Web Panel installer"
	track_install "cwp"
	echo
	sh install.cwp.sh
elif [ -e "/usr/local/vesta" ]; then
	echo "Running csf VestaCP installer"
	track_install "vesta"
	echo
	sh install.vesta.sh
elif [ -e "/usr/local/CyberCP" ]; then
	echo "Running csf CyberPanel installer"
	track_install "cyberpanel"
	echo
	sh install.cyberpanel.sh
else
	echo "Running csf generic installer"
	track_install "generic"
	echo
	sh install.generic.sh
fi
