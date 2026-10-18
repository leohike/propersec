#!/usr/bin/env bash
# The uninstall cases, each in a fresh container from the screenlock-pin-systest image, so no case
# inherits another's damage: install a deliberately broken screenlock-pin, uninstall it, and check
# that the system is as it was (crates/systest/src/uninstall.rs). Exit 1 if any case fails.
# Run after building the image, as `just podman` does; CI runs it as root.

set -uo pipefail
image=screenlock-pin-systest
systest=/opt/screenlock-pin/screenlock-pin-systest

cases=$(podman run --rm --network=none "$image" "$systest" uninstall-cases) || exit 1
failed=0 total=0
for case in $cases; do
    total=$((total + 1))
    podman run --rm --init --network=none "$image" "$systest" uninstall-case "$case" || failed=$((failed + 1))
done
echo
echo "$((total - failed)) passed, $failed failed"
((failed == 0))
