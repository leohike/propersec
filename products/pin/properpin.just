# properpin -- a PIN for the KDE lock screen, within limits. The Rust workspace is at the repo root.
# Nothing here installs anything on this machine or touches its /etc or /run: every recipe works in
# target/, a temporary directory, or a podman container. packaging/install.sh is the installer,
# and no recipe runs it outside a fake root or a container.

# Recipes run at the workspace root, where Cargo.toml and target/ are.
set working-directory := "../.."

# Build the properpin command, the setuid helper and pam_properpin.so
build:
    cargo build -p properpin-cli -p properpin-helper -p pam_properpin

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

# Format everything
fmt:
    cargo fmt --all

# The whole lifecycle in a temporary directory, through the real helper binary (not setgid, so its --dev options work): set, refused, armed, unlocked, three failures, refused
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -q -p properpin-cli -p properpin-helper
    bin="$PWD/target/debug"
    root=$(mktemp -d)
    trap 'rm -rf "$root"' EXIT
    mkdir "$root/run" "$root/var" && chmod 1770 "$root/run" "$root/var"
    # Stands in for unix_chkpwd: accepts the password "correct horse battery staple".
    printf '#!/bin/bash\nIFS= read -r -d "" p\n[[ $p == "correct horse battery staple" ]]\n' >"$root/unix_chkpwd"
    printf '#!/bin/sh\nexec %s "$@" --dev-etc %s --dev-run %s --dev-budget %s --dev-chkpwd %s --dev-log %s\n' \
        "$bin/properpin-helper" "$root/etc" "$root/run" "$root/var" "$root/unix_chkpwd" "$root/log" >"$root/helper"
    chmod +x "$root/unix_chkpwd" "$root/helper"
    properpin() { "$bin/properpin" --etc "$root/etc" --budget "$root/var" --helper "$root/helper" --owner "$(id -u)" --group "$(id -g)" "$@"; }
    step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
    said() { tail -n 1 "$root/log"; }
    lock_screen() { step "lock screen: $1"; echo -n "$1" | "$root/helper" check || true; said; }
    step "properpin set (4859, typed twice)"; printf '4859\n4859\n' | properpin set
    step "properpin status"; properpin status
    lock_screen 4859
    step "lock screen: the correct password, so the arm line runs"
    echo -n "correct horse battery staple" | "$root/helper" arm; said
    lock_screen 4859
    for wrong in 1111 2222 3333; do lock_screen "$wrong"; done
    lock_screen 4859
    step "properpin status"; properpin status

# Everything for real in a stock Fedora 44 container: install.sh, the real /etc/pam.d, pam_unix and unix_chkpwd. Never touches this machine's PAM
podman:
    podman build --quiet --ignorefile products/pin/testing/podman/Containerfile.containerignore -f products/pin/testing/podman/Containerfile -t properpin-systest .
    podman run --rm --network=none properpin-systest
