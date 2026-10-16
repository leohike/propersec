# propersec. Only properpin for now, so its recipes work both directly (`just test`) and under its
# namespace (`just properpin test`); `just --list` shows them all.

# List the recipes
[private]
default:
    @just --justfile {{ justfile() }} --list

import "products/pin/properpin.just"
mod properpin "products/pin/module.just"

# Format all Rust code in the workspace
fmt:
    cargo fmt --all

alias format := fmt
