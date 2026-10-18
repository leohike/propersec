#!/usr/bin/env bash
# properpin's lines in the lock screen's PAM file, /etc/pam.d/kde. install.sh never touches it;
# this is the only thing that does, and only when you run it.
#
#   integrate-into-pam.sh add     after a diff and a yes: properpin's two lines into /etc/pam.d/kde,
#                                 just above and just below its "auth substack password-auth" line,
#                                 replacing any properpin lines already there, an older version's
#                                 included. First saves the file as it is without them, as
#                                 /etc/properpin/kde.pam.without-properpin, for you to go back to by
#                                 hand; nothing reads it back. Refuses unless properpin is installed
#   integrate-into-pam.sh remove  after a diff and a yes: every properpin line out of /etc/pam.d/kde.
#                                 install.sh uninstall refuses until this is done
#   integrate-into-pam.sh check   whether /etc/pam.d/kde has exactly this version's lines (exit 0),
#                                 no properpin lines at all (exit 3), or anything else (exit 1);
#                                 changes nothing and needs no root
#
# Options:
#   --yes        add, remove: don't ask (for scripted tests in a container)
#   --root DIR   tests only: the PAM file and properpin's files under DIR instead of /
#
# properpin's lines are every line naming pam_properpin.so, and what versions before 2026-10-18 put
# around theirs: the "# properpin" marker lines and the pam_unix.so line between their two. Nothing
# else in the file ever changes, and nothing ever deletes it. (Deleting /etc/pam.d/kde would hand
# the lock screen to the "other" service, which denies everyone.)

set -euo pipefail
umask 022

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

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
copy=/etc/properpin/kde.pam.without-properpin
module_path=/usr/local/lib64/security/pam_properpin.so
pam_lines=$here/kde-auth.pam
stock_auth='^auth[[:space:]]+substack[[:space:]]+password-auth([[:space:]]|$)'
# A line naming the module, and what versions before 2026-10-18 put around theirs: the marker
# lines, and a pam_unix line no stock file has.
properpin_line='pam_properpin|^# properpin|^auth[[:space:]]+\[success=ok default=die\][[:space:]]+pam_unix\.so[[:space:]]+use_first_pass[[:space:]]*$'
how_to_add="just integrate-into-pam, or: sudo packaging/integrate-into-pam.sh add"
how_to_remove="just remove-from-pam, or: sudo packaging/integrate-into-pam.sh remove"

# The two lines from packaging/kde-auth.pam, without its comments, and the stock line between them.
mapfile -t shipped < <(grep -v -e '^#' -e '^[[:space:]]*$' "$pam_lines")
if [[ ${#shipped[@]} != 3 || ! ${shipped[1]} =~ $stock_auth || ${shipped[0]} != *"$module_path check" || ${shipped[2]} != *"$module_path housekeeping" ]]; then
    fail "$pam_lines isn't properpin's check and housekeeping lines around the stock auth substack line"
fi
above=${shipped[0]} below=${shipped[2]}

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# --- helpers

# Whether the PAM file has anything of properpin's.
has_properpin() {
    [[ -f $file ]] && grep -qE "$properpin_line" "$file"
}

# Into $scratch/without, the PAM file without anything of properpin's, and into $scratch/with, that
# with this version's lines around the stock auth line. Fails when that line isn't there exactly
# once, leaving in $stock how many times it is.
stock=0
wanted() {
    grep -vE "$properpin_line" "$file" >"$scratch/without" || true
    stock=$(grep -cE "$stock_auth" "$scratch/without" || true)
    [[ $stock == 1 ]] || return 1
    awk -v above="$above" -v below="$below" -v stock="$stock_auth" \
        '$0 ~ stock { print above; print; print below; next } { print }' "$scratch/without" >"$scratch/with"
}

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
    temporary="$(dirname "$dest")/.$(basename "$dest").properpin-new"
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
    if ! has_properpin; then
        echo "$pam_file has no properpin lines, so the lock screen takes the password only; to offer the PIN: $how_to_add"
        exit 3
    fi
    if wanted && cmp -s "$scratch/with" "$file"; then
        echo "$pam_file has the lines this version ships"
        return 0
    fi
    echo "$pam_file has properpin lines, but not exactly the ones this version ships around its auth substack password-auth line (an older version's, or edited by hand), so the PIN may be refused, while the password still works; $how_to_add replaces them, and $how_to_remove takes them out"
    exit 1
}

do_add() {
    require_root
    [[ ! -L $file ]] || fail "$pam_file is a symbolic link; nothing was changed"
    [[ -f $file ]] || fail "$pam_file is missing; nothing was changed"
    # A PAM line naming a module that isn't there locks the lock screen.
    [[ -f $root$module_path && ! -L $root$module_path && -d $root$(dirname "$copy") ]] ||
        fail "properpin isn't installed ($module_path is missing), and lines naming a missing module would lock the lock screen; install it first, with just install; nothing was changed"
    if ! wanted; then
        echo "$pam_file has $stock 'auth substack password-auth' lines, not 1, so this script can't tell where properpin's lines go. To put them in by hand, the first goes just above the line that checks the password, and the second just below it:" >&2
        printf '%s\n' "$above" "$below" >&2
        fail "nothing was changed"
    fi
    if cmp -s "$scratch/with" "$file"; then
        echo "$pam_file already has the lines this version ships"
        return 0
    fi
    confirm "$scratch/with"
    put "$copy" <"$scratch/without"
    put "$pam_file" <"$scratch/with"
    echo "$pam_file has properpin's lines, and was saved without them as $copy"
    echo "test the lock screen before you close a root shell: the PIN, a wrong PIN, and the password"
}

do_remove() {
    require_root
    if ! has_properpin; then
        echo "$pam_file has no properpin lines; nothing to do"
        return 0
    fi
    [[ ! -L $file ]] || fail "$pam_file is a symbolic link; nothing was changed"
    grep -vE "$properpin_line" "$file" >"$scratch/without" || true
    confirm "$scratch/without"
    put "$pam_file" <"$scratch/without"
    echo "took properpin's lines out of $pam_file, so the lock screen takes the password only"
}

"do_$command"
