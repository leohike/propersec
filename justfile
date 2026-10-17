# properpin -- a PIN for the KDE lock screen, within limits. Every recipe works in target/, a
# temporary directory, or a podman container, and never touches this machine's /etc or /run, except
# install, check and uninstall: they run packaging/install.sh on this machine, through sudo.

# List the recipes
[private]
default:
    @just --justfile {{ justfile() }} --list

# Build the properpin command, the setgid pinchecker and pam_properpin.so, for development: with this machine's toolchain, into target/debug. What gets installed comes from release
build:
    cargo build -p properpin-cli -p properpin-pinchecker -p pam_properpin

# The release build of the module, the setgid pinchecker and the command, made with Fedora 44's own toolchain in a podman container whatever this machine has (Homebrew's included), into target/properpin, where install.sh looks by default; then checked to load only the system's libraries, as install checks it again
release:
    podman build --ignorefile testing/podman/Containerfile.containerignore -f packaging/Containerfile -o target/properpin .
    packaging/install.sh check-build --from target/properpin

# Build the release and install it on this machine, or update an earlier install: install.sh shows the change to /etc/pam.d/kde and asks first, then everything is checked. Installs whatever is checked out, uncommitted edits included. Run as yourself, not with sudo, so podman builds in your own image store
install: _not-root release
    @echo "installing properpin $(git describe --always --dirty)"
    sudo packaging/install.sh install
    sudo packaging/install.sh check

# Check what is installed on this machine: every file, the group, and properpin's lines in /etc/pam.d/kde
check: _not-root
    sudo packaging/install.sh check

# Take properpin out of /etc/pam.d/kde on this machine, then remove its files; keeps /etc/properpin, /var/lib/properpin and the properpin group
uninstall: _not-root
    sudo packaging/install.sh uninstall

[private]
_not-root:
    @[ "$(id -u)" -ne 0 ] || { echo "run just as yourself, not as root: the recipe uses sudo itself, and podman under sudo would build in root's image store and leave target/ owned by root" >&2; exit 1; }

# Every test: the rules, files and hashing, the CLI, and the PAM stack through the system's libpam
test *args:
    cargo test --workspace {{ args }}

# Only the PAM stack: the built .so, loaded and run by the system's libpam
smoke:
    cargo test -p pam_properpin --test stack

# clippy with warnings as errors, then a formatting check
lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check

# Mutation testing of core and sys, slow (CI runs it weekly): each change to the code that no test notices is listed in mutants.out/missed.txt. Needs cargo-mutants, and stays on half the CPUs
mutants:
    CARGO_BUILD_JOBS=2 taskset -c 0-$(( $(nproc) / 2 - 1 )) nice -n 10 cargo mutants --package properpin-core --package properpin-sys --test-package properpin-core --test-package properpin-sys --test-package properpin-pinchecker --jobs 2

# The whole lifecycle in a temporary directory, through the real pinchecker binary (not setgid, so its --dev options work): set, the PIN at once, three failures pause it, the password unpauses it
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -q -p properpin-cli -p properpin-pinchecker
    bin="$PWD/target/debug"
    root=$(mktemp -d)
    trap 'rm -rf "$root"' EXIT
    mkdir "$root/var" && chmod 1770 "$root/var"
    # Stands in for unix_chkpwd, and for /etc/shadow: the password is "correct horse battery staple".
    printf '#!/bin/bash\nIFS= read -r -d "" p\n[[ $p == "correct horse battery staple" ]]\n' >"$root/unix_chkpwd"
    printf '%s:%s:20000:0:99999:7:::\n' "$(id -un)" "$(printf 'correct horse battery staple' | mkpasswd -s -m yescrypt 2>/dev/null || echo '!')" >"$root/shadow"
    printf '#!/bin/sh\nexec %s "$@" --dev-etc %s --dev-budget %s --dev-chkpwd %s --dev-log %s\n' \
        "$bin/properpin-pinchecker" "$root/etc" "$root/var" "$root/unix_chkpwd" "$root/log" >"$root/pinchecker"
    chmod +x "$root/unix_chkpwd" "$root/pinchecker"
    properpin() { "$bin/properpin" --etc "$root/etc" --budget "$root/var" --shadow "$root/shadow" --pinchecker "$root/pinchecker" --owner "$(id -u)" --group "$(id -g)" "$@"; }
    step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
    said() { tail -n 1 "$root/log"; }
    lock_screen() { step "lock screen: $1"; echo -n "$1" | "$root/pinchecker" check || true; said; }
    step "properpin set (cat4859, typed twice)"; printf 'cat4859\ncat4859\n' | properpin set
    step "properpin status"; properpin status
    lock_screen cat4859
    for wrong in 1111 2222 3333; do lock_screen "$wrong"; done
    lock_screen cat4859
    step "lock screen: the correct password, so the housekeeping line runs"
    echo -n "correct horse battery staple" | "$root/pinchecker" housekeeping; said
    lock_screen cat4859
    step "properpin status"; properpin status

# Everything for real in a stock Fedora 44 container: install.sh, the real /etc/pam.d, pam_unix and unix_chkpwd. Never touches this machine's PAM
podman:
    podman build --quiet --ignorefile testing/podman/Containerfile.containerignore -f testing/podman/Containerfile -t properpin-systest .
    podman run --rm --init --network=none properpin-systest

# install.sh uninstall against deliberately broken installs, one fresh container per case (after podman builds the image)
podman-uninstall: podman
    testing/podman/uninstall-cases.sh

# Format all Rust code in the workspace
fmt:
    cargo fmt --all

alias format := fmt
