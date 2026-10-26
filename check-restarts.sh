#!/bin/sh
# Executed over SSH. Only inspect restart state; never restart anything.
set -eu
LC_ALL=C
PATH=$PATH:/usr/sbin:/sbin
export LC_ALL PATH

reboot=UNKNOWN
running_kernel=$(uname -r)
printf 'Running kernel: %s\n' "$running_kernel"
if [ -e /run/reboot-required ] || [ -e /var/run/reboot-required ]; then
    reboot=YES
    echo 'Reboot-required marker is present.'
fi
if [ -f /run/reboot-required.pkgs ]; then
    echo 'Packages requesting reboot:'
    cat /run/reboot-required.pkgs
elif [ -f /var/run/reboot-required.pkgs ]; then
    echo 'Packages requesting reboot:'
    cat /var/run/reboot-required.pkgs
fi

checked=0
unavailable='kernel or microcode status could not be determined'
if ! command -v needrestart >/dev/null 2>&1; then
    unavailable='needrestart is not installed'
elif [ "$(id -u)" = 0 ]; then
    needrestart_output=$(needrestart -b -r l </dev/null)
    checked=1
elif [ "${1:-0}" = 1 ]; then
    needrestart_output=$(sudo -n needrestart -b -r l </dev/null)
    checked=1
else
    unavailable='needrestart needs root access; use --needrestart-sudo'
fi

if [ "$checked" = 1 ]; then
    printf '%s\n' "$needrestart_output" | grep -q '^NEEDRESTART-VER: '
    if [ "${2:-0}" = 1 ]; then printf '%s\n' "$needrestart_output";
    else printf '%s\n' "$needrestart_output" | sed -n 's/^NEEDRESTART-SVC: /Restart service: /p'; fi
    kernel=$(printf '%s\n' "$needrestart_output" | sed -n 's/^NEEDRESTART-KSTA: //p')
    microcode=$(printf '%s\n' "$needrestart_output" | sed -n 's/^NEEDRESTART-UCSTA: //p')
    case "$kernel" in ''|0|1|2|3) ;; *) echo 'Invalid needrestart kernel status' >&2; exit 1 ;; esac
    case "$microcode" in ''|0|1|2) ;; *) echo 'Invalid needrestart microcode status' >&2; exit 1 ;; esac
    if [ "$kernel" = 2 ] || [ "$kernel" = 3 ] || [ "$microcode" = 2 ]; then
        reboot=YES
    elif [ "$reboot" != YES ] && [ "$kernel" = 1 ] && [ "$microcode" = 1 ]; then
        reboot=NO
    fi
fi
if [ "$reboot" = UNKNOWN ]; then printf 'Reboot required: UNKNOWN (%s)\n' "$unavailable";
else printf 'Reboot required: %s\n' "$reboot"; fi
