#!/usr/bin/env bash
# Run in the Containerfile's build stage, after the real build: one directory per broken variant
# under /out/broken, each holding libpam_properpin.so, properpin-pinchecker and properpin under exactly
# the real names, so install.sh --from installs it exactly as it installs the real thing. Each
# variant is the real build with one part swapped for a broken one from crates/brokenpin.
# crates/systest's uninstall cases install them and check that install.sh uninstall repairs the
# damage. Never anywhere install.sh looks by default.

set -euo pipefail
cd /src
release=target/release

variant() {
    mkdir -p "/out/broken/$1"
    cp "$release/libpam_properpin.so" "$release/properpin-pinchecker" "$release/properpin" "/out/broken/$1/"
}

for feature in panics segfaults sleeps says-yes; do
    cargo build --release --locked -p brokenpin --features "$feature"
    variant "module-$feature"
    cp "$release/libbrokenpin.so" "/out/broken/module-$feature/libpam_properpin.so"
done

# Without a feature: a module with no pam_sm_authenticate.
cargo build --release --locked -p brokenpin
variant module-missing-symbol
cp "$release/libbrokenpin.so" /out/broken/module-missing-symbol/libpam_properpin.so

for pinchecker in pinchecker-says-yes pinchecker-sleeps; do
    variant "$pinchecker"
    cp "$release/$pinchecker" "/out/broken/$pinchecker/properpin-pinchecker"
done
