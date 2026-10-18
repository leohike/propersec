#!/usr/bin/env bash
# Set pin_unpause_by in /etc/properpin/config: what tells properpin that the lock screen was
# unlocked with the password, so the PIN is unpaused (README-BIG.md, The PAM lines). Every other
# line of the config stays as it is. Shows the change, then writes it without asking: the config is
# properpin's own, and a bad one refuses the PIN alone, never the password.
#
#   set-pin-unpause-by.sh password-check  the pinchecker checks the password itself (the default)
#   set-pin-unpause-by.sh setcred         pam_setcred after a successful unlock, no password read
#   set-pin-unpause-by.sh both            each of the two
#
# Options:
#   --root DIR   tests only: the config under DIR instead of /

set -euo pipefail
umask 022

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

fail() {
    echo "set-pin-unpause-by.sh: $*" >&2
    exit 1
}

mode="" root=/
while [[ $# -gt 0 ]]; do
    case $1 in
        --root) root=${2:?--root needs a directory}; shift 2 ;;
        password-check | setcred | both) [[ -z $mode ]] || usage; mode=$1; shift ;;
        *) usage ;;
    esac
done
[[ -n $mode ]] || usage

root=$(realpath -m "$root")
[[ $root == / ]] && root=""
real=$([[ -z $root ]] && echo 1 || echo 0)

config_path=/etc/properpin/config
config=$root$config_path
dir=$(dirname "$config")

if [[ $real == 1 && $(id -u) != 0 ]]; then
    fail "it writes $config_path, so it needs root; run it with sudo"
fi
[[ -d $dir && ! -L $dir ]] || fail "$(dirname "$config_path") is missing, so properpin isn't installed; install it first, with just install"
[[ ! -L $config ]] || fail "$config_path is a symbolic link; nothing was changed"
[[ ! -e $config || -f $config ]] || fail "$config_path is not a regular file; nothing was changed"

# Built beside the config, then renamed over it, so the pinchecker never reads half a file.
new=$(mktemp "$dir/.config.properpin-new.XXXXXX")
trap 'rm -f "$new"' EXIT
{
    if [[ -f $config ]]; then
        grep -vE '^[[:space:]]*pin_unpause_by[[:space:]]*=' "$config" || true
    fi
    echo "pin_unpause_by = $mode"
} >"$new"

if [[ -f $config ]] && cmp -s "$new" "$config"; then
    echo "$config_path already has pin_unpause_by = $mode"
    exit 0
fi
diff -u --label "$config_path" --label "$config_path (new)" "$([[ -f $config ]] && echo "$config" || echo /dev/null)" "$new" || true
chmod 0644 "$new"
if [[ $real == 1 ]]; then
    chown root:root "$new"
fi
mv -f "$new" "$config"
trap - EXIT
if [[ $real == 1 ]] && command -v selinuxenabled >/dev/null && selinuxenabled; then
    restorecon -F "$config"
fi
echo "$config_path has pin_unpause_by = $mode"
