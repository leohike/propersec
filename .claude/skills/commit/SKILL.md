---
name: commit
description: Commit and push the current changes in this repo. Use whenever the user asks to commit (including "commit", "commit this", "commit and push", "commit X and Y"), or invokes /commit.
---

Commits go through the bundled script, which commits, adds an `Assisted-by:` trailer naming the model of this session, and pushes with `--force-with-lease --force-if-includes`. It has two staging modes:

- **Commit all (default).** When the user just says "commit", run the script with no argument: it stages everything with `git add -A`. Check `git status` first for anything that should not be committed (secrets, build output, scratch files); if something should stay out, add it to `.gitignore` or ask the user rather than silently committing it.
- **Commit only staged (`--staged`).** When the user names what to commit ("commit this and that", "commit only the README fix"), stage exactly those changes yourself with `git add <paths>` (or `git add -p` equivalents via `git apply --cached` for partial files), confirm with `git diff --cached --stat`, then run the script with `--staged`. It commits the index as is and leaves everything else unstaged in the working tree.

Write the commit message yourself: a short subject line, a blank line, and a body if the change needs one. Do NOT add `Co-Authored-By:`, `Assisted-by:` or any other attribution line — the script adds the only attribution. Pass the message on stdin:

```bash
"${CLAUDE_SKILL_DIR}/commit.sh" <<'EOF'
Subject line

Optional body.
EOF
```

```bash
git add path/one path/two
"${CLAUDE_SKILL_DIR}/commit.sh" --staged <<'EOF'
Subject line
EOF
```

Exit codes: 0 committed (and pushed, unless the script says there was no remote), 1 nothing to commit (or nothing staged with `--staged`), 2 empty message or unknown argument, 3 committed but the push was rejected. On 3, stop and report it to the user; never retry with `--force` or a `+branch` refspec.
