#!/usr/bin/env bash
# Stage everything (or, with --staged, keep the index as is), commit with the
# message read from stdin plus an Assisted-by trailer naming the model of the
# calling Claude Code session, then push with --force-with-lease --force-if-includes.
set -euo pipefail

stage_all=1
case "${1:-}" in
  "") ;;
  --staged) stage_all=0 ;;
  *) echo "commit.sh: unknown argument: $1 (only --staged is accepted)" >&2; exit 2 ;;
esac

msg=$(cat)
if [[ -z "${msg//[[:space:]]/}" ]]; then
  echo "commit.sh: empty commit message on stdin" >&2
  exit 2
fi
# Drop leading whitespace and blank lines, then capitalize the first letter.
msg="${msg#"${msg%%[![:space:]]*}"}"
msg="${msg^}"

# Latest model ID recorded in this session's transcript; "<synthetic>" marks
# messages Claude Code generates itself, so skip those.
model=""
if [[ -n "${CLAUDE_CODE_SESSION_ID:-}" ]]; then
  config_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
  for transcript in "$config_dir"/projects/*/"$CLAUDE_CODE_SESSION_ID".jsonl; do
    [[ -f "$transcript" ]] || continue
    model=$(grep -o '"model":"[^"]*"' "$transcript" | grep -v '"<synthetic>"' | tail -n 1 | cut -d'"' -f4 || true)
    [[ -n "$model" ]] && break
  done
fi
model="${model:-unspecified AI agent}"

if (( stage_all )); then
  git add -A
fi
if git diff --cached --quiet; then
  echo "commit.sh: nothing to commit$( (( stage_all )) || echo " (nothing staged)")" >&2
  exit 1
fi

printf '%s\n' "$msg" | git commit -F - --trailer "Assisted-by: $model"

if git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1; then
  push=(git push --force-with-lease --force-if-includes)
elif git remote get-url origin >/dev/null 2>&1; then
  push=(git push --force-with-lease --force-if-includes -u origin HEAD)
else
  echo "commit.sh: committed, but no upstream and no origin remote, so nothing was pushed" >&2
  exit 0
fi

if ! "${push[@]}"; then
  echo "commit.sh: committed, but the push was rejected; not retrying with a stronger push" >&2
  exit 3
fi
