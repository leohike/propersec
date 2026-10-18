# screenlock-pin -- a PIN for the KDE lock screen, within limits. Every recipe works in target/, a
# temporary directory, or a podman container, and never touches this machine's /etc or /run, except
# install, check and uninstall, which run packaging/install.sh on this machine, integrate-into-pam
# and remove-from-pam, which run packaging/integrate-into-pam.sh, and logs, which only reads, all
# through sudo. Only integrate-into-pam and remove-from-pam ever touch /etc/pam.d.

# List the recipes
[private]
default:
    @just --justfile {{ justfile() }} --list

# Build the screenlock-pin command, the setgid PIN checker and pam_screenlock_pin.so, for development: with this machine's toolchain, into target/debug. What gets installed comes from release
build:
    cargo build -p screenlock-pin-cli -p screenlock-pin-checker -p pam_screenlock_pin

# The release build of the module, the setgid PIN checker and the command, made with Fedora 44's own toolchain in a podman container whatever this machine has (Homebrew's included), into target/screenlock-pin, where install.sh looks by default; then checked to load only the system's libraries, as install checks it again. podman leaves target/screenlock-pin 0700, so it takes target's mode instead: a checkout shared through its group stays usable by the next user who builds, and no checkout gives anyone more than it already does
release:
    podman build --ignorefile testing/podman/Containerfile.containerignore -f packaging/Containerfile -o target/screenlock-pin .
    chmod --reference=target target/screenlock-pin
    packaging/install.sh check-build --from target/screenlock-pin

# Build the release and install it on this machine, or update an earlier install, then check everything. It never touches /etc/pam.d: it ends by saying whether /etc/pam.d/kde has the lines this version ships, and if not, to run integrate-into-pam. Installs whatever is checked out, uncommitted edits included. Run as yourself, not with sudo, so podman builds in your own image store
install: _not-root release
    @echo "installing screenlock-pin $(git describe --always --dirty)"
    sudo packaging/install.sh install
    sudo packaging/install.sh check

# Print, for pasting into a bug report or a chat, the journal lines of screenlock-pin, of every PAM module on the lock screen's kde service and of kscreenlocker since SINCE (default: 30 minutes ago, any journalctl --since works), then what is installed and how: the checkout, /etc/pam.d/kde, the config, doctor and status. Only prints; writes nothing anywhere. Never shows a PIN or a password, which nothing logs; it does show your user name and the times you unlocked
logs since="30 min ago": _not-root
    #!/usr/bin/env bash
    set -uo pipefail
    section() { printf '\n===== %s\n' "$*"; }
    section "screenlock-pin logs since {{ since }}, printed $(date -Is)"
    section "checkout"
    echo "$(git describe --always --dirty) on branch $(git branch --show-current)"
    ls -l --time-style=full-iso /usr/local/lib64/security/pam_screenlock_pin.so /usr/local/libexec/screenlock-pin/screenlock-pin-checker 2>&1
    section "journal"
    sudo journalctl -q --since "{{ since }}" --no-pager -o short-iso | grep -E 'screenlock-pin-checker\[|pam_[a-z_]+\(kde[:-]|kscreenlocker' || echo "(nothing)"
    section "/etc/pam.d/kde"
    cat /etc/pam.d/kde
    section "integrate-into-pam check"
    packaging/integrate-into-pam.sh check
    section "/etc/screenlock-pin/config"
    sudo cat /etc/screenlock-pin/config 2>/dev/null || echo "(no config: every setting at its default)"
    section "screenlock-pin doctor"
    sudo /usr/local/bin/screenlock-pin doctor 2>&1
    section "screenlock-pin status"
    /usr/local/bin/screenlock-pin status 2>&1
    section "end"

# Check what is installed on this machine: every file, the group, and screenlock-pin's lines in /etc/pam.d/kde, if it has any
check: _not-root
    sudo packaging/install.sh check

# Put screenlock-pin's two lines into /etc/pam.d/kde on this machine, or replace another version's, after showing the change and asking; the PIN works at the lock screen from then on. Saves the file without them as /etc/screenlock-pin/kde.pam.without-screenlock-pin first
integrate-into-pam: _not-root
    sudo packaging/integrate-into-pam.sh add

# Take screenlock-pin's lines out of /etc/pam.d/kde on this machine, after showing the change and asking; the lock screen takes the password only from then on
remove-from-pam: _not-root
    sudo packaging/integrate-into-pam.sh remove

# Remove screenlock-pin's files from this machine; keeps /etc/screenlock-pin, /var/lib/screenlock-pin and the screenlock-pin group. Refuses until remove-from-pam has taken screenlock-pin's lines out of /etc/pam.d/kde
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
    cargo test -p pam_screenlock_pin --test stack

# clippy with warnings as errors, then a formatting check
lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check

# Mutation testing of core and sys, slow (CI runs it weekly): each change to the code that no test notices is listed in mutants.out/missed.txt. Needs cargo-mutants, and stays on half the CPUs
mutants:
    CARGO_BUILD_JOBS=2 taskset -c 0-$(( $(nproc) / 2 - 1 )) nice -n 10 cargo mutants --package screenlock-pin-core --package screenlock-pin-sys --test-package screenlock-pin-core --test-package screenlock-pin-sys --test-package screenlock-pin-checker --jobs 2

# The whole lifecycle in a temporary directory, through the real PIN checker binary (not setgid, so its --dev options work): set, the PIN at once, three failures pause it, the password unpauses it
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -q -p screenlock-pin-cli -p screenlock-pin-checker
    bin="$PWD/target/debug"
    root=$(mktemp -d)
    trap 'rm -rf "$root"' EXIT
    mkdir "$root/var" && chmod 1770 "$root/var"
    # Stands in for /etc/shadow, which set compares the PIN with: the password is "correct horse battery staple".
    printf '%s:%s:20000:0:99999:7:::\n' "$(id -un)" "$(printf 'correct horse battery staple' | mkpasswd -s -m yescrypt 2>/dev/null || echo '!')" >"$root/shadow"
    printf '#!/bin/sh\nexec %s "$@" --dev-etc %s --dev-budget %s --dev-log %s\n' \
        "$bin/screenlock-pin-checker" "$root/etc" "$root/var" "$root/log" >"$root/pin-checker"
    chmod +x "$root/pin-checker"
    screenlock-pin() { "$bin/screenlock-pin" --etc "$root/etc" --budget "$root/var" --shadow "$root/shadow" --pin-checker "$root/pin-checker" --owner "$(id -u)" --group "$(id -g)" "$@"; }
    step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
    said() { tail -n 1 "$root/log"; }
    lock_screen() { step "lock screen: $1"; echo -n "$1" | "$root/pin-checker" check || true; said; }
    step "screenlock-pin set (cat4859, typed twice)"; printf 'cat4859\ncat4859\n' | screenlock-pin set
    step "screenlock-pin status"; screenlock-pin status
    lock_screen cat4859
    for wrong in 1111 2222 3333; do lock_screen "$wrong"; done
    lock_screen cat4859
    step "lock screen: the correct password, so pam_setcred runs the after-password-auth line"
    "$root/pin-checker" unpause </dev/null; said
    lock_screen cat4859
    step "screenlock-pin status"; screenlock-pin status

# Everything for real in a stock Fedora 44 container: install.sh, integrate-into-pam.sh, the real /etc/pam.d, pam_unix and unix_chkpwd. Never touches this machine's PAM
podman:
    podman build --quiet --ignorefile testing/podman/Containerfile.containerignore -f testing/podman/Containerfile -t screenlock-pin-systest .
    podman run --rm --init --network=none screenlock-pin-systest

# integrate-into-pam.sh remove and install.sh uninstall against deliberately broken installs, one fresh container per case (after podman builds the image)
podman-uninstall: podman
    testing/podman/uninstall-cases.sh

# Format all Rust code in the workspace
fmt:
    cargo fmt --all

alias format := fmt
