#!/usr/bin/env bash
# properpin's installer.
#
#   install.sh install     after a diff and a yes: take properpin out of /etc/pam.d/kde, if it is
#                          there; install the properpin group, the module, the setgid pinchecker, the
#                          command, /etc/properpin and /var/lib/properpin; check them; and only then add
#                          the three lines this version ships. Installing again, or a newer version,
#                          is the same command. Also removes /run/properpin, which older versions
#                          used. Then prints what properpin doctor finds in the PINs, budgets and
#                          config, which install never judges or changes
#   install.sh check       every installed path: kind, mode, owner, same bytes as the build, SELinux label,
#                          and what the binaries load; that the group has no members and a locked
#                          password; and that /etc/pam.d/kde has exactly the lines this version ships.
#                          The PINs, budgets and config are properpin doctor's
#   install.sh check-build what the three built files load, as install checks it before it changes
#                          anything; needs no root, and is what `just release` runs
#   install.sh uninstall   take properpin out of /etc/pam.d/kde (its lines, or, if they are damaged,
#                          the copy saved at install, after a diff and a yes), then remove what install
#                          put in place; keeps /etc/properpin, /var/lib/properpin and the properpin group
#
# Options:
#   --from DIR       where the built libpam_properpin.so, properpin-pinchecker and properpin are
#                    (default: target/properpin, where `just release` puts them)
#   --yes            install, uninstall: don't ask (for scripted tests in a container)
#   --root DIR       tests only: install under DIR instead of /
#   --owner USER     tests only: who owns the installed files (default: root)
#   --pinchecker-group GROUP   tests only: the group the pinchecker runs with (default: properpin)
#
# install rewrites properpin's lines every time, so lines from an older version never call a newer
# module. They come out first, so a failure anywhere leaves the lock screen on its stock stack,
# taking the password only, and go back in only once check passes. With the lines in, a user
# without a PIN sees no difference: the module steps aside. Nothing ever deletes /etc/pam.d/kde:
# properpin's lines come out between their two marker lines, and nothing else changes. (Deleting
# /etc/pam.d/kde would hand the lock screen to the "other" service, which denies everyone.)
#
# Each binary must load its libraries from the system's directories alone, which only root can
# change: no search path of its own (RPATH, RUNPATH), the system's loader, and every library found
# under /lib, /lib64, /usr/lib or /usr/lib64. Otherwise whoever can write where it looks, such as
# the owner of /home/linuxbrew when Homebrew's toolchain built it, could put code into the setgid
# pinchecker or into the lock screen. install refuses such a build before it changes anything.

set -euo pipefail
umask 022

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$here")

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

# --- arguments

command="" root=/ owner=root pinchecker_group=properpin from=$repo/target/properpin yes=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --root) root=${2:?--root needs a directory}; shift 2 ;;
        --owner) owner=${2:?--owner needs a user}; shift 2 ;;
        --pinchecker-group) pinchecker_group=${2:?--pinchecker-group needs a group}; shift 2 ;;
        --from) from=${2:?--from needs a directory}; shift 2 ;;
        --yes) yes=1; shift ;;
        install | check | check-build | uninstall) [[ -z $command ]] || usage; command=$1; shift ;;
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
pinchecker=$libexec/properpin-pinchecker
command_path=/usr/local/bin/properpin
etc=/etc/properpin
users=$etc/users
old_run_dir=/run/properpin
budget_dir=/var/lib/properpin
sysusers=/etc/sysusers.d/properpin.conf
tmpfiles=/etc/tmpfiles.d/properpin.conf
pam_file=/etc/pam.d/kde
pam_backup=$etc/kde.pam.without-properpin
# Where versions before 2026-10-17, which had separate enable and disable commands, kept it.
old_pam_backup=$etc/kde.pam.before-enable
pam_damaged=$etc/kde.pam.damaged
# The directories install had to create, which uninstall removes again once they are empty.
created=$etc/install.created-dirs
pam_lines=$here/kde-auth.pam

# Older versions wrote another text after the same beginning, so the begin marker is found by it.
begin_prefix="# properpin begin"
begin_marker="$begin_prefix: added by install.sh install; install.sh uninstall removes everything down to the end marker"
end_marker="# properpin end"
stock_auth='^auth[[:space:]]+substack[[:space:]]+password-auth([[:space:]]|$)'

scratch=$(mktemp -d)
# 1 while install has properpin's lines out of the PAM file, from taking them out to putting them back.
lines_out=0
on_exit() {
    local status=$?
    rm -rf "$scratch"
    if [[ $status != 0 && $lines_out == 1 ]]; then
        echo "install.sh: $pam_file is left without properpin's lines: the lock screen takes the password only, for every user, until install succeeds" >&2
    fi
}
trap on_exit EXIT

built_module=$from/libpam_properpin.so
built_binary=$from/properpin
built_pinchecker=$from/properpin-pinchecker

wrapper() {
    cat <<EOF
#!/bin/sh
# Installed by properpin's install.sh: the properpin command with this machine's paths.
exec $binary --etc $etc --budget $budget_dir --pinchecker $pinchecker "\$@"
EOF
}

# The group the pinchecker runs with: a system group with no members, so no account at all.
# systemd-sysusers reads this.
sysusers_conf() {
    echo "# Installed by properpin's install.sh: the group properpin-pinchecker runs with."
    echo "g $pinchecker_group -"
}

# /var/lib/properpin, the budgets of failures, which only the pinchecker's group can enter. Sticky, so
# each user's run of the pinchecker can only replace that user's own files. The rule only keeps it in
# shape, since tmpfiles never empties a d directory without an age.
tmpfiles_conf() {
    echo "# Installed by properpin's install.sh: properpin-pinchecker's budgets."
    echo "d $budget_dir 1770 $owner $pinchecker_group -"
}

# --- helpers

# Write stdin to $root$1 with mode $2, owned by $3 (default: the owner): built beside it, then
# renamed over it, so nothing ever sees a missing or half-written file. chown comes before chmod,
# because chown clears the setgid bit.
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

# mkdir -p, noting in $created_now each directory that didn't exist yet, parents first.
created_now=()
make_dirs() {
    local dir path part parts
    for dir in "$@"; do
        path=""
        IFS=/ read -ra parts <<<"${dir#/}"
        for part in "${parts[@]}"; do
            path=$path/$part
            if [[ ! -e $root$path ]]; then
                mkdir "$root$path"
                created_now+=("$path")
            fi
        done
    done
}

# A directory properpin owns: created if missing, and always given its owner and mode, by default
# the owner's and 0755.
own_dir() {
    install -d -m "${2:-0755}" -o "${3:-$owner}" -g "${4:-$group}" "$root$1"
}

# Create the pinchecker's group on the real system, unless it exists. In a fake root it must exist
# already: tests name their own group. No user is ever created.
ensure_group() {
    if getent group "$pinchecker_group" >/dev/null; then
        return 0
    fi
    [[ $real == 1 ]] || fail "no group named $pinchecker_group"
    if command -v systemd-sysusers >/dev/null; then
        systemd-sysusers "$root$sysusers"
    else
        groupadd --system "$pinchecker_group"
    fi
    getent group "$pinchecker_group" >/dev/null || fail "could not create the $pinchecker_group group"
}

selinux_enabled() {
    [[ $real == 1 ]] && command -v selinuxenabled >/dev/null && selinuxenabled
}

relabel() {
    if selinux_enabled; then
        restorecon -RF "$@"
    fi
}

# Anything of properpin's in stdin: a marker, or a line naming the module.
mentions_properpin() {
    grep -qE '^# properpin|pam_properpin'
}

# The three auth lines from packaging/kde-auth.pam, without its comments, between the markers.
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
    awk -v begin="$begin_prefix" -v end="$end_marker" 'index($0, begin) == 1 { skip = 1 } !skip { print } $0 == end { skip = 0 }'
}

# Only properpin's block from stdin, markers included.
only_block() {
    awk -v begin="$begin_prefix" -v end="$end_marker" 'index($0, begin) == 1 { keep = 1 } keep { print } $0 == end { keep = 0 }'
}

# Write to $scratch/without the PAM file without properpin's block, and succeed only if that
# removes everything of properpin's cleanly: one begin and one end marker, nothing of properpin's
# left outside them, and the stock auth line still there.
without_block() {
    local file=$root$pam_file
    [[ $(grep -c "^$begin_prefix" "$file") == 1 && $(grep -cxF "$end_marker" "$file") == 1 ]] || return 1
    remove_block <"$file" >"$scratch/without"
    ! mentions_properpin <"$scratch/without" && grep -qE "$stock_auth" "$scratch/without"
}

# Work out the PAM file without anything of properpin's, into $scratch/without, changing nothing
# yet. $pam_state says what that took: clean (there was nothing of properpin's), block (its block
# taken out), restore (the file is damaged or missing, or lost its stock auth line, so it is the copy
# saved at install), or absent (no file and no copy). Fails when it can't be worked out.
pam_state=""
without_properpin() {
    local file=$root$pam_file backup=$root$pam_backup
    # Versions before 2026-10-17 kept the copy under another name.
    if [[ -f $root$old_pam_backup && ! -L $root$old_pam_backup && ! -e $backup ]]; then
        mv "$root$old_pam_backup" "$backup"
    fi
    if [[ ! -e $file && ! -e $backup ]]; then
        pam_state=absent
    elif [[ -f $file ]] && ! mentions_properpin <"$file" && { grep -qE "$stock_auth" "$file" || [[ ! -e $backup ]]; }; then
        cp "$file" "$scratch/without"
        pam_state=clean
    elif [[ -f $file ]] && without_block; then
        pam_state=block
    else
        [[ -f $backup && ! -L $backup ]] ||
            fail "$pam_file is damaged or missing, and there is no copy saved at install ($pam_backup); fix it by hand: take out every line naming properpin; nothing was changed"
        if mentions_properpin <"$backup" || ! grep -qE "$stock_auth" "$backup"; then
            fail "the copy saved at install ($pam_backup) doesn't look like the stock file; fix $pam_file by hand; nothing was changed"
        fi
        cp "$backup" "$scratch/without"
        pam_state=restore
    fi
}

# Write what without_properpin worked out to the PAM file, keeping a damaged file it replaces.
# Never leaves the PAM file naming a module that is about to be replaced or deleted.
take_out_of_pam() {
    case $pam_state in
        clean | absent) return 0 ;;
        block) echo "took properpin's lines out of $pam_file" ;;
        restore)
            echo "$pam_file is damaged or missing, so it goes back to the copy saved at install"
            if [[ -f $root$pam_file ]]; then
                cp "$root$pam_file" "$root$pam_damaged"
                echo "the damaged file is kept as $pam_damaged"
            fi
            ;;
    esac
    put "$pam_file" 0644 <"$scratch/without"
    relabel "$root$pam_file"
    if [[ $pam_state == restore ]]; then
        echo "$pam_file is again exactly as it was before properpin's lines went in"
    fi
}

# Show what changes in the PAM file and, on the real system, ask before writing it. A missing PAM
# file shows as empty.
confirm() {
    local new=$1
    diff -u --label "$pam_file" --label "$pam_file (new)" <(cat "$root$pam_file" 2>/dev/null) "$new" || true
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
        fail "$command needs root (it writes to /usr/local and /etc, or reads /etc/gshadow); run it with sudo"
    fi
}

# --- what the binaries load

# Whether $1 is in the system's own library directories, which only root can change.
in_system_libraries() {
    [[ $1 =~ ^(/usr)?/lib(64)?/ && $1 != */../* && $1 != */./* ]]
}

# Adding to $problems what is wrong with what $1, called $2 in what is said, loads when it starts.
check_linkage() {
    local file=$1 name=$2 dynamic interpreter line library path
    command -v readelf >/dev/null || fail "readelf, from binutils, is needed to check what $name loads; nothing was changed"
    if ! dynamic=$(readelf -d "$file" 2>/dev/null) || ! grep -q '(NEEDED)' <<<"$dynamic"; then
        problems+=("$name: not a binary that loads the system's libraries")
        return
    fi
    while IFS= read -r line; do
        problems+=("$name: has a library search path of its own, $line, so whoever can write there can put code into it")
    done < <(sed -nE 's/.*\((RPATH|RUNPATH)\).*\[(.*)\]$/\1 \2/p' <<<"$dynamic")
    interpreter=$(readelf -l "$file" 2>/dev/null | sed -nE 's/.*Requesting program interpreter: (.*)\]$/\1/p')
    if [[ -n $interpreter ]] && ! in_system_libraries "$interpreter"; then
        problems+=("$name: started by the loader $interpreter, not the system's")
    fi
    # Without the variables that would make the loader look elsewhere for this run only.
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+=\>[[:space:]]+(.*)[[:space:]]\(0x ]]; then
            library=${BASH_REMATCH[1]} path=${BASH_REMATCH[2]}
        elif [[ $line =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+=\>[[:space:]]+not\ found ]]; then
            problems+=("$name: needs ${BASH_REMATCH[1]}, which isn't on this system")
            continue
        elif [[ $line =~ ^[[:space:]]*(/[^[:space:]]+)[[:space:]]\(0x ]]; then
            library=${BASH_REMATCH[1]} path=${BASH_REMATCH[1]}
        else
            continue
        fi
        in_system_libraries "$path" || problems+=("$name: loads $library from $path, outside the system's library directories")
    done < <(env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT ldd "$file" 2>/dev/null || true)
}

# What the three built files load, failing with every problem found.
check_build() {
    [[ -f $built_module && -f $built_binary && -f $built_pinchecker ]] ||
        fail "no build in $from; run: just release (it builds in a Fedora container), or pass --from with your own build"
    check_linkage "$built_module" "$built_module"
    check_linkage "$built_binary" "$built_binary"
    check_linkage "$built_pinchecker" "$built_pinchecker"
    if ((${#problems[@]})); then
        printf '%s\n' "${problems[@]}" >&2
        fail "the build in $from doesn't load only the system's libraries; nothing was changed. just release builds it with Fedora's toolchain, in a container"
    fi
}

# --- commands

do_check-build() {
    check_build
    echo "build OK, as expected: everything in $from loads only system libraries, from directories only root can change, so no one else can slip code into the pinchecker or the lock screen"
}

do_install() {
    require_root
    check_build
    [[ ! -L $root$pam_file ]] || fail "$pam_file is a symbolic link; nothing was changed"
    without_properpin
    [[ $pam_state != absent ]] || fail "$pam_file is missing; nothing was changed"
    local stock
    stock=$(grep -cE "$stock_auth" "$scratch/without" || true)
    [[ $stock == 1 ]] || fail "$pam_file has $stock 'auth substack password-auth' lines, not 1; nothing was changed"
    grep -qF "$module_path " "$pam_lines" || fail "$pam_lines doesn't load $module_path"
    add_block <"$scratch/without" >"$scratch/with"
    # The change must be exactly reversible before it is made.
    remove_block <"$scratch/with" | cmp -s - "$scratch/without" || fail "uninstall couldn't undo this change; nothing was changed"
    if cmp -s "$scratch/with" "$root$pam_file"; then
        echo "$pam_file already has the lines this version ships"
    else
        confirm "$scratch/with"
    fi

    # From here on, anything that fails leaves the lock screen on its stock stack.
    take_out_of_pam
    lines_out=1
    make_dirs "$(dirname "$module_path")" "$(dirname "$command_path")" "$(dirname "$sysusers")" "$(dirname "$tmpfiles")" "$(dirname "$libexec")" "$(dirname "$budget_dir")"
    sysusers_conf | put "$sysusers" 0644
    tmpfiles_conf | put "$tmpfiles" 0644
    ensure_group
    own_dir "$libexec"
    # properpin's alone, so emptied: whatever an older version left there goes, such as the setgid
    # properpin-helper of versions before the pinchecker's rename.
    find "$root$libexec" -mindepth 1 -delete
    own_dir "$etc"
    # Added to what an earlier install noted, never replacing it.
    if ((${#created_now[@]})); then
        { printf '%s\n' "${created_now[@]}"; cat "$root$created" 2>/dev/null || true; } | sort -u | put "$created" 0644
    fi
    own_dir "$users" 0750 "$owner" "$pinchecker_group"
    own_dir "$budget_dir" 1770 "$owner" "$pinchecker_group"
    rm -rf -- "$root$old_run_dir"
    put "$module_path" 0755 <"$built_module"
    put "$binary" 0755 <"$built_binary"
    put "$pinchecker" 2755 "$owner:$pinchecker_group" <"$built_pinchecker"
    wrapper | put "$command_path" 0755
    relabel "$root$module_path" "$root$libexec" "$root$command_path" "$root$etc" "$root$budget_dir" "$root$sysusers" "$root$tmpfiles"
    if ! check_files; then
        printf '%s\n' "${problems[@]}"
        fail "the installed files don't check out"
    fi

    cp "$scratch/without" "$root$pam_backup.properpin-new"
    mv -f "$root$pam_backup.properpin-new" "$root$pam_backup"
    put "$pam_file" 0644 <"$scratch/with"
    lines_out=0
    relabel "$root$pam_file" "$root$pam_backup"
    echo "installed under ${root:-/}; $pam_file has properpin's lines, and was saved without them as $pam_backup"
    echo "the lock screen offers the PIN to each user who sets one with: sudo properpin set"
    # Only reported: a PIN doctor finds fault with is refused for its user alone, never for anyone else.
    echo "properpin doctor:"
    "$root$binary" --etc "$root$etc" --budget "$root$budget_dir" --pinchecker "$root$pinchecker" \
        --owner "$(id -u "$owner")" --group "$pinchecker_group" doctor | sed 's/^/  /' || true
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

# The pinchecker's group, on the real system: anyone who has it can read every PIN hash and change
# everyone's counts, so only running the pinchecker may give it. No members, nobody's primary group, and
# a locked password, so newgrp can't give it either. Reading gshadow needs root, as check does.
check_group() {
    local entry gid members primary password
    entry=$(getent group "$pinchecker_group")
    gid=$(cut -d: -f3 <<<"$entry")
    members=$(cut -d: -f4 <<<"$entry")
    [[ -z $members ]] || problems+=("group $pinchecker_group: has members ($members); it must have none")
    primary=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid { print $1 }' | paste -sd, -)
    [[ -z $primary ]] || problems+=("group $pinchecker_group: the primary group of $primary; it must be nobody's")
    password=$(getent gshadow "$pinchecker_group" | cut -d: -f2) || true
    [[ $password == [\!*]* ]] || problems+=("group $pinchecker_group: its password in /etc/gshadow isn't locked; it must start with ! or *")
}

# Every installed file, adding to $problems what is wrong. Not the PINs, budgets or config, which
# install doesn't write: properpin doctor judges them, by the pinchecker's own rules.
check_files() {
    if ! getent group "$pinchecker_group" >/dev/null; then
        problems+=("no group named $pinchecker_group; install again")
        return 1
    fi
    if [[ $real == 1 ]]; then
        check_group
    fi
    expect "$module_path" file 755 "$owner" "$group"
    expect "$libexec" dir 755 "$owner" "$group"
    if [[ -d $root$libexec && ! -L $root$libexec ]]; then
        local extra
        while IFS= read -r -d '' extra; do
            problems+=("$libexec/$extra: not installed by this version; install again, which removes it")
        done < <(find "$root$libexec" -mindepth 1 -maxdepth 1 ! -name "$(basename "$binary")" ! -name "$(basename "$pinchecker")" -printf '%f\0')
    fi
    expect "$binary" file 755 "$owner" "$group"
    expect "$pinchecker" file 2755 "$owner" "$pinchecker_group"
    expect "$command_path" file 755 "$owner" "$group"
    expect "$sysusers" file 644 "$owner" "$group"
    expect "$tmpfiles" file 644 "$owner" "$group"
    expect "$etc" dir 755 "$owner" "$group"
    expect "$users" dir 750 "$owner" "$pinchecker_group"
    expect "$budget_dir" dir 1770 "$owner" "$pinchecker_group"
    local installed
    for installed in "$module_path" "$binary" "$pinchecker"; do
        if [[ -f $root$installed && ! -L $root$installed ]]; then
            check_linkage "$root$installed" "$installed"
        fi
    done
    if [[ -f $built_module ]]; then
        expect_bytes "$module_path" "$built_module"
        expect_bytes "$binary" "$built_binary"
        expect_bytes "$pinchecker" "$built_pinchecker"
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
    if selinux_enabled; then
        local path
        for path in "$module_path" "$libexec" "$binary" "$pinchecker" "$command_path" "$etc" "$users" "$budget_dir" "$sysusers" "$tmpfiles"; do
            matchpathcon -V "$path" >/dev/null 2>&1 || problems+=("$path: wrong SELinux label; install again")
        done
    elif [[ $real == 1 ]]; then
        echo "SELinux is not enabled here, so labels weren't checked"
    fi
    ((${#problems[@]} == 0))
}

# properpin's lines in the PAM file, adding to $problems what is wrong.
check_pam() {
    local file=$root$pam_file
    if [[ ! -f $file ]] || ! mentions_properpin <"$file"; then
        problems+=("$pam_file: has no properpin lines, so the lock screen takes the password only; install again")
    elif ! without_block; then
        problems+=("$pam_file: damaged around properpin's lines; install again, or uninstall, which put back the copy saved at install")
    elif ! diff -q <(properpin_block) <(only_block <"$file") >/dev/null; then
        problems+=("$pam_file: properpin's lines are not the ones this version ships; install again")
    fi
}

do_check() {
    require_root
    check_files || true
    check_pam
    if ((${#problems[@]})); then
        printf '%s\n' "${problems[@]}"
        return 1
    fi
    echo "all properpin files in place under ${root:-/}, and $pam_file has the lines this version ships"
}

do_uninstall() {
    require_root
    without_properpin
    if [[ $pam_state == block || $pam_state == restore ]]; then
        confirm "$scratch/without"
    fi
    take_out_of_pam
    rm -f "$root$module_path" "$root$command_path" "$root$sysusers" "$root$tmpfiles"
    # properpin's own directory, whatever else ended up in it.
    rm -rf -- "$root$libexec"
    # Left by versions with a pepper, if install never ran since.
    rm -rf -- "$root$old_run_dir"
    # The directories install created, deepest first, as long as nothing else has moved in.
    if [[ -f $root$created ]]; then
        local dir
        while IFS= read -r dir; do
            if [[ $dir == /* && -d $root$dir && ! -L $root$dir ]]; then
                rmdir --ignore-fail-on-non-empty -- "$root$dir"
            fi
        done < <(sort -r "$root$created")
        rm -f "$root$created"
    fi
    echo "uninstalled; $etc is kept, with any PINs and the PAM backup, and so are $budget_dir, with each"
    echo "user's budget of failures, and the $pinchecker_group group those files belong to. To remove them all:"
    echo "rm -r $etc $budget_dir && groupdel $pinchecker_group"
}

"do_$command"
