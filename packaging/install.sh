#!/usr/bin/env bash
# properpin's installer. It never touches /etc/pam.d: integrate-into-pam.sh, next to it, puts
# properpin's lines into /etc/pam.d/kde and takes them out, and only when you run it.
#
#   install.sh install     install the properpin group, the module, the setgid pinchecker, the
#                          command, /etc/properpin and /var/lib/properpin, and check them. Installing
#                          again, or a newer version, is the same command. Also removes /run/properpin,
#                          which older versions used. Then says whether /etc/pam.d/kde has the lines
#                          this version ships, and prints what properpin doctor finds in the PINs,
#                          budgets and config, which install never judges or changes
#   install.sh check       every installed path: kind, mode, owner, same bytes as the build, SELinux label,
#                          and what the binaries load; that the group has no members and a locked
#                          password; and that properpin's lines in /etc/pam.d/kde, if it has any, are
#                          exactly the ones this version ships. The PINs, budgets and config are
#                          properpin doctor's
#   install.sh check-build what the three built files load, as install checks it before it changes
#                          anything; needs no root, and is what `just release` runs
#   install.sh uninstall   remove what install put in place; keeps /etc/properpin, /var/lib/properpin
#                          and the properpin group. Refuses while /etc/pam.d/kde has properpin's lines,
#                          since lines naming a deleted module lock the lock screen:
#                          integrate-into-pam.sh remove takes them out first
#
# Options:
#   --from DIR       where the built libpam_properpin.so, properpin-pinchecker and properpin are
#                    (default: target/properpin, where `just release` puts them)
#   --root DIR       tests only: install under DIR instead of /
#   --owner USER     tests only: who owns the installed files (default: root)
#   --pinchecker-group GROUP   tests only: the group the pinchecker runs with (default: properpin)
#
# Each file is replaced by a rename, so a lock screen already using properpin never sees a missing
# or half-written one. Pieces that don't fit together, after a failure partway or with an older
# version's lines still in /etc/pam.d/kde, only ever refuse the PIN: the module steps aside from
# anything it can't use, and the password works as always.
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

command="" root=/ owner=root pinchecker_group=properpin from=$repo/target/properpin
while [[ $# -gt 0 ]]; do
    case $1 in
        --root) root=${2:?--root needs a directory}; shift 2 ;;
        --owner) owner=${2:?--owner needs a user}; shift 2 ;;
        --pinchecker-group) pinchecker_group=${2:?--pinchecker-group needs a group}; shift 2 ;;
        --from) from=${2:?--from needs a directory}; shift 2 ;;
        install | check | check-build | uninstall) [[ -z $command ]] || usage; command=$1; shift ;;
        *) usage ;;
    esac
done
[[ -n $command ]] || usage

root=$(realpath -m "$root")
[[ $root == / ]] && root=""
real=$([[ -z $root ]] && echo 1 || echo 0)
group=$(id -gn "$owner") || fail "no user named $owner"

# --- what goes where. The command spells out the same real paths whatever --root is: it describes
# the installed system, not the directory it was installed into for a test.

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
# The directories install had to create, which uninstall removes again once they are empty.
created=$etc/install.created-dirs

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

# What integrate-into-pam.sh check says about the PAM file, in $pam_said, and its exit code, in
# $pam_code: 0 for exactly this version's lines, 3 for no properpin lines at all, 1 for anything else.
pam_said="" pam_code=0
check_pam() {
    pam_code=0
    pam_said=$("$here/integrate-into-pam.sh" check --root "${root:-/}" 2>&1) || pam_code=$?
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
    make_dirs "$(dirname "$module_path")" "$(dirname "$command_path")" "$(dirname "$sysusers")" "$(dirname "$tmpfiles")" "$(dirname "$libexec")" "$(dirname "$budget_dir")"
    sysusers_conf | put "$sysusers" 0644
    tmpfiles_conf | put "$tmpfiles" 0644
    ensure_group
    own_dir "$libexec"
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
    # properpin's alone, so anything else goes, such as the setgid properpin-helper of versions
    # before the pinchecker's rename. Only after the new pinchecker is in place, so there is always one.
    find "$root$libexec" -mindepth 1 -maxdepth 1 ! -name "$(basename "$binary")" ! -name "$(basename "$pinchecker")" -exec rm -rf -- {} +
    wrapper | put "$command_path" 0755
    relabel "$root$module_path" "$root$libexec" "$root$command_path" "$root$etc" "$root$budget_dir" "$root$sysusers" "$root$tmpfiles"
    if ! check_files; then
        printf '%s\n' "${problems[@]}"
        fail "the installed files don't check out"
    fi

    echo "installed under ${root:-/}"
    check_pam
    echo "$pam_said"
    echo "with the lines in, the lock screen offers the PIN to each user who sets one with: sudo properpin set"
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

do_check() {
    require_root
    check_files || true
    check_pam
    if [[ $pam_code != 0 && $pam_code != 3 ]]; then
        problems+=("$pam_said")
    fi
    if ((${#problems[@]})); then
        printf '%s\n' "${problems[@]}"
        return 1
    fi
    echo "all properpin files in place under ${root:-/}"
    echo "$pam_said"
}

do_uninstall() {
    require_root
    check_pam
    [[ $pam_code == 3 ]] ||
        fail "$pam_file still has properpin's lines, which would lock the lock screen once the module is gone; take them out first, with just remove-from-pam, or: sudo packaging/integrate-into-pam.sh remove; nothing was removed"
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
    echo "uninstalled; $etc is kept, with any PINs and the copy of $pam_file without properpin's lines, and"
    echo "so are $budget_dir, with each user's budget of failures, and the $pinchecker_group group those files"
    echo "belong to. To remove them all: rm -r $etc $budget_dir && groupdel $pinchecker_group"
}

"do_$command"
