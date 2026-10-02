# propersec: one module per product. `just --list properpin` shows its recipes.

mod properpin "products/pin/properpin.just"

# List the recipes
[private]
default:
    @just --list

# Log gh in with a GitHub token typed at a hidden prompt, so CI runs and their logs can be read; pushes stay on SSH
github-login:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
    read -rsp "GitHub token (input hidden): " token
    echo
    [[ -n $token ]] || { echo "no token given; nothing changed" >&2; exit 1; }
    gh auth login --hostname github.com --with-token <<<"$token"
    unset token
    gh auth status --hostname github.com
    # The token must read this repo's Actions runs, which is what watching CI needs.
    gh api "repos/{owner}/{repo}/actions/runs?per_page=1" --silent && echo "Actions runs: readable"
