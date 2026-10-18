#!/usr/bin/env bash
# screenlock-pin's one line in the lock screen's PAM file, /etc/pam.d/kde. This is the only thing that
# ever edits that file, and only when you run it. install.sh puts screenlock-pin's own PAM file,
# /etc/pam.d/screenlock-auth, next to it, which does nothing until kde names it.
#
#   integrate-into-pam.sh add     after a diff and a yes: one word in /etc/pam.d/kde, its stock line
#                                 "auth substack password-auth" becomes "auth substack screenlock-auth",
#                                 so the lock screen checks the PIN first, then the password as before.
#                                 Refuses unless screenlock-pin is installed, and on a file with
#                                 anything of properpin's or of an earlier screenlock-pin's in it
#   integrate-into-pam.sh remove  after a diff and a yes: that word changed back, so /etc/pam.d/kde is
#                                 stock again, byte for byte. install.sh uninstall refuses until this
#                                 is done
#   integrate-into-pam.sh check   whether /etc/pam.d/kde has screenlock-pin's line (exit 0), nothing of
#                                 screenlock-pin's (exit 3), or anything else (exit 1), the line while
#                                 /etc/pam.d/screenlock-auth is missing among them; changes nothing and
#                                 needs no root
#
# Options:
#   --yes        add, remove: don't ask (for scripted tests in a container)
#   --root DIR   tests only: the PAM file and screenlock-pin's files under DIR instead of /
#
# Nothing else in the file ever changes, and nothing ever deletes it. (Deleting /etc/pam.d/kde would
# hand the lock screen to the "other" service, which denies everyone.)

set -euo pipefail
umask 022

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

fail() {
    echo "integrate-into-pam.sh: $*" >&2
    exit 1
}

# --- arguments

command="" root=/ yes=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --root) root=${2:?--root needs a directory}; shift 2 ;;
        --yes) yes=1; shift ;;
        add | remove | check) [[ -z $command ]] || usage; command=$1; shift ;;
        *) usage ;;
    esac
done
[[ -n $command ]] || usage

root=$(realpath -m "$root")
[[ $root == / ]] && root=""
real=$([[ -z $root ]] && echo 1 || echo 0)

pam_file=/etc/pam.d/kde
file=$root$pam_file
auth_name=screenlock-auth
auth_file=/etc/pam.d/$auth_name
module_path=/usr/local/lib64/security/pam_screenlock_pin.so
# The stock line and screenlock-pin's, which differ in one word; whatever follows it stays as it is.
stock_line='^(auth[[:space:]]+substack[[:space:]]+)password-auth(([[:space:]].*)?)$'
own_line="^(auth[[:space:]]+substack[[:space:]]+)$auth_name(([[:space:]].*)?)\$"
# Anything of screenlock-pin's, own line or not. Earlier versions named the module in kde itself,
# around the stock line, and so did properpin, as screenlock-pin was called until 2026-10-18.
any_trace="$auth_name|pam_screenlock_pin|properpin"
how_to_add="just integrate-into-pam, or: sudo packaging/integrate-into-pam.sh add"
how_to_remove="just remove-from-pam, or: sudo packaging/integrate-into-pam.sh remove"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# --- helpers

# How many lines of the PAM file match $1.
count() {
    grep -cE "$1" "$file" || true
}

# What the PAM file has of screenlock-pin's, in $state: none; own, exactly screenlock-pin's line in
# place of the stock one; or other, with $why saying what. $stock counts the stock lines.
state="" why="" stock=0
look() {
    state=none stock=0
    [[ -f $file ]] || return 0
    stock=$(count "$stock_line")
    local own others
    own=$(count "$own_line")
    others=$(grep -E "$any_trace" "$file" | grep -cvE "$own_line" || true)
    if ((own == 0 && others == 0)); then
        return 0
    fi
    state=other
    if grep -qE properpin "$file"; then
        why="has lines of properpin, as screenlock-pin was called until 2026-10-18"
    elif grep -qE pam_screenlock_pin "$file"; then
        why="names pam_screenlock_pin.so itself, as an earlier screenlock-pin's lines did"
    elif ((own != 1 || others != 0 || stock != 0)); then
        why="has $auth_name, but not only as the one line this version puts in place of the stock one (edited by hand?)"
    else
        state=own
    fi
}

# What to do with a file this version doesn't take as it is.
by_hand="put it back as stock by hand, then $how_to_add"

require_root() {
    if [[ $real == 1 && $(id -u) != 0 ]]; then
        fail "$command needs root, since it writes $pam_file; run it with sudo"
    fi
}

# Show what changes in the PAM file and, on the real system, ask before writing it.
confirm() {
    diff -u --label "$pam_file" --label "$pam_file (new)" "$file" "$1" || true
    if [[ $real == 0 || $yes == 1 ]]; then
        return 0
    fi
    [[ -t 0 ]] || fail "no terminal to confirm on; nothing changed (--yes skips the question)"
    local answer
    read -r -p "Write $pam_file? Keep a root shell open until you have tested the lock screen. [y/N] " answer
    [[ $answer == y ]] || fail "nothing changed"
}

# Write stdin to $root$1, mode 0644: built beside it, then renamed over it, so nothing ever sees a
# missing or half-written file. Then its SELinux label, on the real system.
put() {
    local dest=$root$1
    local temporary
    temporary="$(dirname "$dest")/.$(basename "$dest").screenlock-pin-new"
    rm -f "$temporary"
    cat >"$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$dest"
    if [[ $real == 1 ]] && command -v selinuxenabled >/dev/null && selinuxenabled; then
        restorecon -F "$dest"
    fi
}

# --- commands

do_check() {
    look
    case $state in
        none)
            echo "$pam_file has no screenlock-pin line, so the lock screen takes the password only; to offer the PIN: $how_to_add"
            exit 3
            ;;
        own)
            if [[ -f $root$auth_file ]]; then
                echo "$pam_file has screenlock-pin's line, auth substack $auth_name"
                return 0
            fi
            echo "$pam_file names $auth_name, but $auth_file is missing, so the lock screen refuses everyone, the password too; install screenlock-pin again (just install), or take the line out with $how_to_remove"
            ;;
        other)
            echo "$pam_file $why, so the PIN may be refused, while the password still works; this version only changes a stock file: $by_hand"
            ;;
    esac
    exit 1
}

do_add() {
    require_root
    [[ ! -L $file ]] || fail "$pam_file is a symbolic link; nothing was changed"
    [[ -f $file ]] || fail "$pam_file is missing; nothing was changed"
    # kde naming a missing file locks the lock screen.
    [[ -f $root$auth_file && ! -L $root$auth_file && -f $root$module_path && ! -L $root$module_path ]] ||
        fail "screenlock-pin isn't installed ($auth_file or $module_path is missing), and $pam_file naming a missing $auth_name would lock the lock screen; install it first, with just install; nothing was changed"
    look
    case $state in
        own)
            echo "$pam_file already has screenlock-pin's line"
            return 0
            ;;
        other) fail "$pam_file $why; this version only changes a stock file: $by_hand; nothing was changed" ;;
    esac
    if [[ $stock != 1 ]]; then
        echo "$pam_file has $stock 'auth substack password-auth' lines, not 1, so this script can't tell which line checks the password. To do it by hand, change password-auth to $auth_name on that line" >&2
        fail "nothing was changed"
    fi
    sed -E "s/$stock_line/\\1$auth_name\\2/" "$file" >"$scratch/with"
    confirm "$scratch/with"
    put "$pam_file" <"$scratch/with"
    echo "$pam_file has screenlock-pin's line, so the lock screen checks the PIN first, through $auth_file; to change it back: $how_to_remove"
    echo "test the lock screen before you close a root shell: the PIN, a wrong PIN, and the password"
}

do_remove() {
    require_root
    look
    if [[ $state == none ]]; then
        echo "$pam_file has no screenlock-pin line; nothing to do"
        return 0
    fi
    [[ ! -L $file ]] || fail "$pam_file is a symbolic link; nothing was changed"
    [[ $state == own ]] || fail "$pam_file $why, which this version doesn't take out: $by_hand; nothing was changed"
    sed -E "s/$own_line/\\1password-auth\\2/" "$file" >"$scratch/without"
    confirm "$scratch/without"
    put "$pam_file" <"$scratch/without"
    echo "changed $pam_file back to auth substack password-auth, so the lock screen takes the password only"
}

"do_$command"
