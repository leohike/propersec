#!/usr/bin/env bash
# properpin's installer.
#
#   install.sh install     the properpin account, the module, the setuid helper, the command,
#                          /etc/properpin and /run/properpin; never touches PAM
#   install.sh check       every installed path: kind, mode, owner, same bytes as the build, SELinux label
#   install.sh enable      add properpin's three lines to /etc/pam.d/kde, after a diff and a yes
#   install.sh disable     take exactly those lines out again, after a diff and a yes
#   install.sh uninstall   remove what install put in place; refuses while enabled; keeps /etc/properpin
#                          and the properpin account
#
# Options:
#   --from DIR       where the built libpam_properpin.so, properpin-helper and properpin are
#                    (default: target/release)
#   --yes            enable, disable: don't ask (for scripted tests in a container)
#   --root DIR       tests only: install under DIR instead of /
#   --owner USER     tests only: who owns the installed files (default: root)
#   --account USER   tests only: the account the helper runs as (default: properpin)
#
# Installing the files and enabling them in PAM are separate steps on purpose: everything can be
# installed and checked while the lock screen still runs its stock stack. disable never deletes
# /etc/pam.d/kde: it removes the lines enable added, between their two marker lines, and nothing
# else. (Deleting /etc/pam.d/kde would hand the lock screen to the "other" service, which denies
# everyone.)

set -euo pipefail
umask 022

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
product=$(dirname "$here")
repo=$(dirname "$(dirname "$product")")

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

# --- arguments

command="" root=/ owner=root account=properpin from=$repo/target/release yes=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --root) root=${2:?--root needs a directory}; shift 2 ;;
        --owner) owner=${2:?--owner needs a user}; shift 2 ;;
        --account) account=${2:?--account needs a user}; shift 2 ;;
        --from) from=${2:?--from needs a directory}; shift 2 ;;
        --yes) yes=1; shift ;;
        install | check | enable | disable | uninstall) [[ -z $command ]] || usage; command=$1; shift ;;
        *) usage ;;
    esac
done
[[ -n $command ]] || usage

root=$(realpath -m "$root")
[[ $root == / ]] && root=""
real=$([[ -z $root ]] && echo 1 || echo 0)
group=$(id -gn "$owner") || fail "no user named $owner"

# --- what goes where. The PAM lines and the command spell out the same real paths whatever --root
# is: they describe the installed system, not the directory it was installed into for a test.

module_path=/usr/local/lib64/security/pam_properpin.so
libexec=/usr/local/libexec/properpin
binary=$libexec/properpin
helper=$libexec/properpin-helper
command_path=/usr/local/bin/properpin
etc=/etc/properpin
users=$etc/users
run_dir=/run/properpin
sysusers=/etc/sysusers.d/properpin.conf
tmpfiles=/etc/tmpfiles.d/properpin.conf
pam_file=/etc/pam.d/kde
pam_backup=$etc/kde.pam.before-enable
pam_lines=$product/pam/kde-auth.pam

begin_marker="# properpin begin: added by install.sh enable; install.sh disable removes everything down to the end marker"
end_marker="# properpin end"
stock_auth='^auth[[:space:]]+substack[[:space:]]+password-auth([[:space:]]|$)'

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

built_module=$from/libpam_properpin.so
built_binary=$from/properpin
built_helper=$from/properpin-helper

wrapper() {
    cat <<EOF
#!/bin/sh
# Installed by properpin's install.sh: the properpin command with this machine's paths.
exec $binary --etc $etc --helper $helper "\$@"
EOF
}

# The account the helper runs as: a system account, no home, no login. systemd-sysusers reads this.
sysusers_conf() {
    echo "# Installed by properpin's install.sh: the account properpin-helper runs as."
    echo "u $account - \"properpin lock-screen PIN helper\" - -"
}

# /run/properpin, created again at every boot: the helper's per-boot state, for its account only.
tmpfiles_conf() {
    echo "# Installed by properpin's install.sh: properpin-helper's per-boot state."
    echo "d $run_dir 0700 $account $account -"
}

# --- helpers

# Write stdin to $root$1 with mode $2, owned by $3 (default: the owner): built beside it, then
# renamed over it, so nothing ever sees a missing or half-written file. chown comes before chmod,
# because chown clears the setuid bit.
put() {
    local dest=$root$1 mode=$2 who=${3:-$owner:$group}
    local temporary
    temporary="$(dirname "$dest")/.$(basename "$dest").properpin-new"
    rm -f "$temporary"
    cat >"$temporary"
    chown "$who" "$temporary"
    chmod "$mode" "$temporary"
    mv -f "$temporary" "$dest"
}

# A directory properpin owns: created if missing, and always given its owner and mode, by default
# the owner's and 0755.
own_dir() {
    install -d -m "${2:-0755}" -o "${3:-$owner}" -g "${4:-$group}" "$root$1"
}

# Create the helper's account on the real system, unless it exists. In a fake root it must exist
# already: tests name their own account.
ensure_account() {
    if id -u "$account" >/dev/null 2>&1; then
        return 0
    fi
    [[ $real == 1 ]] || fail "no account named $account"
    if command -v systemd-sysusers >/dev/null; then
        systemd-sysusers "$sysusers"
    else
        useradd --system --user-group --no-create-home --home-dir / --shell /usr/sbin/nologin \
            --comment "properpin lock-screen PIN helper" "$account"
    fi
    id -u "$account" >/dev/null 2>&1 || fail "could not create the $account account"
}

selinux_enabled() {
    [[ $real == 1 ]] && command -v selinuxenabled >/dev/null && selinuxenabled
}

relabel() {
    if selinux_enabled; then
        restorecon -RF "$@"
    fi
}

is_enabled() {
    [[ -f $root$pam_file ]] && grep -qxF "$begin_marker" "$root$pam_file"
}

# The three auth lines from pam/kde-auth.pam, without its comments, between the markers.
properpin_block() {
    echo "$begin_marker"
    grep -v -e '^#' -e '^[[:space:]]*$' "$pam_lines"
    echo "$end_marker"
}

# stdin with properpin's block inserted above the stock auth substack line.
add_block() {
    awk -v block="$(properpin_block)" -v stock="$stock_auth" '$0 ~ stock && !done { print block; done = 1 } { print }'
}

# stdin without properpin's block.
remove_block() {
    awk -v begin="$begin_marker" -v end="$end_marker" '$0 == begin { skip = 1 } !skip { print } $0 == end { skip = 0 }'
}

# Show what changes in the PAM file and, on the real system, ask before writing it.
confirm() {
    local new=$1
    diff -u --label "$pam_file" --label "$pam_file (new)" "$root$pam_file" "$new" || true
    if [[ $real == 0 || $yes == 1 ]]; then
        return 0
    fi
    [[ -t 0 ]] || fail "no terminal to confirm on; nothing changed (--yes skips the question)"
    local answer
    read -r -p "Write $pam_file? Keep a root shell open until you have tested the lock screen. [y/N] " answer
    [[ $answer == y ]] || fail "nothing changed"
}

require_root() {
    if [[ $real == 1 && $(id -u) != 0 ]]; then
        fail "$command writes to /usr/local and /etc; run it with sudo"
    fi
}

# --- commands

# User files from before the helper (readable by each user's own group) can't be read by the helper,
# and their users can read them. They are refused rather than converted: set those PINs again.
refuse_old_layout() {
    [[ -d $root$users ]] || return 0
    local user_file
    for user_file in "$root$users"/*; do
        [[ -e $user_file ]] || continue
        [[ $(stat -c %G "$user_file") == "$account_group" ]] ||
            fail "$users/$(basename "$user_file") is from an older properpin (group $(stat -c %G "$user_file"), not $account_group); remove it, install, and set that PIN again"
    done
}

do_install() {
    require_root
    [[ -f $built_module && -f $built_binary && -f $built_helper ]] ||
        fail "no build in $from; run: cargo build --release -p pam_properpin -p properpin-helper -p properpin-cli"
    mkdir -p "$root$(dirname "$module_path")" "$root$(dirname "$command_path")" "$root$(dirname "$sysusers")" "$root$(dirname "$tmpfiles")"
    sysusers_conf | put "$sysusers" 0644
    tmpfiles_conf | put "$tmpfiles" 0644
    ensure_account
    account_group=$(id -gn "$account")
    refuse_old_layout
    own_dir "$libexec"
    own_dir "$etc"
    own_dir "$users" 0750 "$owner" "$account_group"
    mkdir -p "$root$(dirname "$run_dir")"
    own_dir "$run_dir" 0700 "$account" "$account_group"
    put "$module_path" 0755 <"$built_module"
    put "$binary" 0755 <"$built_binary"
    put "$helper" 6755 "$account:$account_group" <"$built_helper"
    wrapper | put "$command_path" 0755
    relabel "$root$module_path" "$root$libexec" "$root$command_path" "$root$etc" "$root$run_dir" "$root$sysusers" "$root$tmpfiles"
    echo "installed under ${root:-/}; /etc/pam.d/kde is unchanged"
    echo "next: install.sh check, then install.sh enable"
}

problems=()

# Expect $1 to be a $2 (file, dir) with mode $3, owned by $4:$5.
expect() {
    local path=$root$1 kind=$2 mode=$3 user=$4 grp=$5
    if [[ ! -e $path && ! -L $path ]]; then
        problems+=("$1: missing")
        return
    fi
    if [[ -L $path ]] || { [[ $kind == file ]] && [[ ! -f $path ]]; } || { [[ $kind == dir ]] && [[ ! -d $path ]]; }; then
        problems+=("$1: not a $kind")
        return
    fi
    local actual
    actual=$(stat -c '%a %U:%G' "$path")
    [[ $actual == "$mode $user:$grp" ]] || problems+=("$1: is $actual, should be $mode $user:$grp")
}

expect_bytes() {
    [[ -f $root$1 ]] || return 0
    cmp -s "$root$1" "$2" || problems+=("$1: differs from $2; install again")
}

do_check() {
    if ! id -u "$account" >/dev/null 2>&1; then
        echo "no account named $account; install again"
        return 1
    fi
    account_group=$(id -gn "$account")
    expect "$module_path" file 755 "$owner" "$group"
    expect "$libexec" dir 755 "$owner" "$group"
    expect "$binary" file 755 "$owner" "$group"
    expect "$helper" file 6755 "$account" "$account_group"
    expect "$command_path" file 755 "$owner" "$group"
    expect "$sysusers" file 644 "$owner" "$group"
    expect "$tmpfiles" file 644 "$owner" "$group"
    expect "$etc" dir 755 "$owner" "$group"
    expect "$users" dir 750 "$owner" "$account_group"
    expect "$run_dir" dir 700 "$account" "$account_group"
    if [[ -e $root$etc/config ]]; then
        expect "$etc/config" file 644 "$owner" "$group"
    fi
    if [[ -f $built_module ]]; then
        expect_bytes "$module_path" "$built_module"
        expect_bytes "$binary" "$built_binary"
        expect_bytes "$helper" "$built_helper"
    else
        echo "no build in $from, so the installed bytes weren't compared"
    fi
    if [[ -f $root$command_path ]] && ! diff -q <(wrapper) "$root$command_path" >/dev/null; then
        problems+=("$command_path: not the wrapper install.sh writes; install again")
    fi
    if [[ -f $root$sysusers ]] && ! diff -q <(sysusers_conf) "$root$sysusers" >/dev/null; then
        problems+=("$sysusers: not what install.sh writes; install again")
    fi
    if [[ -f $root$tmpfiles ]] && ! diff -q <(tmpfiles_conf) "$root$tmpfiles" >/dev/null; then
        problems+=("$tmpfiles: not what install.sh writes; install again")
    fi
    if [[ -d $root$users ]]; then
        local user_file name
        for user_file in "$root$users"/*; do
            [[ -e $user_file ]] || continue
            name=$(basename "$user_file")
            # Each user's file is readable by the helper's group only, not by the user.
            expect "$users/$name" file 640 "$owner" "$account_group"
        done
    fi
    if selinux_enabled; then
        local path
        for path in "$module_path" "$libexec" "$binary" "$helper" "$command_path" "$etc" "$users" "$run_dir" "$sysusers" "$tmpfiles"; do
            matchpathcon -V "$path" >/dev/null 2>&1 || problems+=("$path: wrong SELinux label; install again")
        done
    elif [[ $real == 1 ]]; then
        echo "SELinux is not enabled here, so labels weren't checked"
    fi
    if ((${#problems[@]})); then
        printf '%s\n' "${problems[@]}"
        return 1
    fi
    echo "all properpin files in place under ${root:-/}"
    if is_enabled; then
        echo "$pam_file has properpin's lines: the lock screen offers the PIN"
    else
        echo "$pam_file has no properpin lines: the lock screen takes the password only"
    fi
}

do_enable() {
    require_root
    [[ -f $root$pam_file && ! -L $root$pam_file ]] || fail "$pam_file is missing or not a regular file"
    is_enabled && fail "$pam_file already has properpin's lines"
    grep -q '^# properpin' "$root$pam_file" && fail "$pam_file has a stray properpin marker; fix it by hand"
    local stock
    stock=$(grep -cE "$stock_auth" "$root$pam_file" || true)
    [[ $stock == 1 ]] || fail "$pam_file has $stock 'auth substack password-auth' lines, not 1; not touching it"
    grep -qF "$module_path " "$pam_lines" || fail "$pam_lines doesn't load $module_path"
    do_check >/dev/null || fail "the installed files don't check out, so $pam_file was left alone; run: install.sh check"

    local new=$scratch/kde
    add_block <"$root$pam_file" >"$new"
    # The change must be exactly reversible before it is made.
    remove_block <"$new" | cmp -s - "$root$pam_file" || fail "disable couldn't undo this change; not touching $pam_file"
    confirm "$new"
    cp "$root$pam_file" "$root$pam_backup.properpin-new"
    mv -f "$root$pam_backup.properpin-new" "$root$pam_backup"
    put "$pam_file" 0644 <"$new"
    relabel "$root$pam_file" "$root$pam_backup"
    echo "enabled; $pam_file was saved as $pam_backup; undo with: install.sh disable"
}

do_disable() {
    require_root
    if ! is_enabled; then
        echo "$pam_file has no properpin lines; nothing to do"
        return 0
    fi
    [[ $(grep -cxF "$begin_marker" "$root$pam_file") == 1 && $(grep -cxF "$end_marker" "$root$pam_file") == 1 ]] ||
        fail "$pam_file doesn't have exactly one begin and one end marker; fix it by hand"
    local new=$scratch/kde
    remove_block <"$root$pam_file" >"$new"
    grep -qE "$stock_auth" "$new" || fail "without properpin's lines, $pam_file would have no 'auth substack password-auth'; not touching it"
    confirm "$new"
    put "$pam_file" 0644 <"$new"
    relabel "$root$pam_file"
    if [[ -f $root$pam_backup ]] && cmp -s "$root$pam_file" "$root$pam_backup"; then
        echo "disabled; $pam_file is again exactly as it was before enable"
    else
        echo "disabled; $pam_file differs from the copy saved at enable ($pam_backup), so it changed in between"
    fi
}

do_uninstall() {
    require_root
    is_enabled && fail "$pam_file still has properpin's lines; run install.sh disable first"
    rm -f "$root$module_path" "$root$binary" "$root$helper" "$root$command_path" "$root$sysusers" "$root$tmpfiles"
    [[ -d $root$libexec ]] && rmdir "$root$libexec"
    # Only per-boot state: failure counts and arming times.
    rm -rf "$root$run_dir"
    echo "uninstalled; $etc is kept, with any PINs and the PAM backup, and so is the $account account,"
    echo "which those files belong to. To remove both: rm -r $etc && userdel $account"
}

"do_$command"
