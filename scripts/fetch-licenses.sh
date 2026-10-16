#!/usr/bin/env bash
# Writes the repo's licence texts from SPDX's license-list-data at a pinned
# tag, twice: into LICENSES/, REUSE style (one file per licence, named by its
# SPDX identifier), and as LICENSE-MIT and LICENSE-APACHE at the root, the
# names GitHub's licence detection looks for. Each download must match the
# SHA-256 below, or nothing is written. Existing files that differ are kept
# unless --force is given.
#
# Usage: scripts/fetch-licenses.sh [--force]

set -euo pipefail

SPDX_TAG=v3.29.0
BASE_URL="https://raw.githubusercontent.com/spdx/license-list-data/$SPDX_TAG/text"
MIT_HOLDER="2026 Leo Hike <leo.hike17@gmail.com>"

declare -A SHA256=(
    [MIT]=b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5
    [Apache-2.0]=074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff
)

force=0
case "${1-}" in
    "") ;;
    --force) force=1 ;;
    *) echo "usage: $0 [--force]" >&2; exit 2 ;;
esac

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Download and verify everything before writing anything.
for id in MIT Apache-2.0; do
    curl -fsSL --proto '=https' -o "$tmp/$id.txt" "$BASE_URL/$id.txt"
    actual=$(sha256sum "$tmp/$id.txt" | cut -d' ' -f1)
    if [[ $actual != "${SHA256[$id]}" ]]; then
        echo "error: $id.txt from SPDX $SPDX_TAG has SHA-256 $actual, expected ${SHA256[$id]}; nothing written" >&2
        exit 1
    fi
done

# MIT carries the copyright line; Apache-2.0 stays verbatim (its bracketed
# fields are part of the appendix template and are not filled in).
placeholder='Copyright (c) <year> <copyright holders>'
if [[ $(grep -cxF "$placeholder" "$tmp/MIT.txt") != 1 ]]; then
    echo "error: MIT.txt does not contain the copyright placeholder exactly once; nothing written" >&2
    exit 1
fi
sed -i "s|^Copyright (c) <year> <copyright holders>\$|Copyright (c) $MIT_HOLDER|" "$tmp/MIT.txt"

# Each licence goes to these paths, relative to the repo root.
declare -A TARGETS=(
    [MIT]="LICENSES/MIT.txt LICENSE-MIT"
    [Apache-2.0]="LICENSES/Apache-2.0.txt LICENSE-APACHE"
)

# Refuse to overwrite files that differ, unless forced.
for id in MIT Apache-2.0; do
    for rel in ${TARGETS[$id]}; do
        target="$repo_root/$rel"
        if [[ -e $target ]] && ! cmp -s "$tmp/$id.txt" "$target" && (( ! force )); then
            echo "error: $target exists and differs; rerun with --force to overwrite; nothing written" >&2
            exit 1
        fi
    done
done

for id in MIT Apache-2.0; do
    for rel in ${TARGETS[$id]}; do
        target="$repo_root/$rel"
        mkdir -p "$(dirname "$target")"
        if [[ -e $target ]] && cmp -s "$tmp/$id.txt" "$target"; then
            echo "unchanged: $rel"
        else
            install -m 0644 "$tmp/$id.txt" "$target"
            echo "wrote: $rel"
        fi
    done
done
