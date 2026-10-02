# properpin -- a PIN for the KDE lock screen, within limits. The Rust workspace is at the repo root.
# Nothing here installs anything or touches /etc or /run: every recipe works in target/ or a
# temporary directory.

# Recipes run at the workspace root, where Cargo.toml and target/ are.
set working-directory := "../.."

# Build the properpin command and pam_properpin.so
build:
    cargo build -p properpin-cli -p pam_properpin

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

# The whole lifecycle in a temporary directory: set, refused, armed, unlocked, three failures, refused
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -q -p properpin-cli
    bin="$PWD/target/debug/properpin"
    root=$(mktemp -d)
    trap 'rm -rf "$root"' EXIT
    uid=$(id -u)
    mkdir -p "$root/run/$uid" && chmod 700 "$root/run/$uid"
    properpin() { "$bin" --etc "$root/etc" --run-base "$root/run" --owner "$uid" "$@"; }
    step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
    lock_screen() { step "lock screen: $1"; echo "$1" | properpin dev check || true; }
    step "properpin set (4859, typed twice)"; printf '4859\n4859\n' | properpin set
    step "properpin status"; properpin status
    lock_screen 4859
    step "lock screen: the correct password"; properpin dev arm
    lock_screen 4859
    for wrong in 1111 2222 3333; do lock_screen "$wrong"; done
    lock_screen 4859
    step "properpin status"; properpin status
