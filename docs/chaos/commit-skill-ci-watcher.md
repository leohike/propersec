# Commit skill: a background CI watcher

A tabled improvement to the repo's `commit` skill (`.claude/skills/commit/`), worked out on 2026-10-03 and not built yet. The decisions below were made by the owner in two rounds of questions; the remaining questions are still open.

## Why

After a commit, the main agent used to watch the GitHub Actions run itself (`gh run watch`), which blocked the conversation for the four to six minutes CI takes. The owner wants the main agent never to wait on CI. Instead, the commit skill hands watching to a parallel agent, which reports back when the run is done and fixes easy failures on its own.

Until this is built, the main agent simply doesn't watch CI after committing. It mentions that CI wasn't checked, and checks only when asked.

## What it would do

After `commit.sh` has committed and pushed:

- **The main agent runs a quick preflight** (`ci-watch.sh --preflight`). If `gh` is missing, not logged in, or `origin` isn't on GitHub, it prints one line, such as "CI not watched: gh not logged in; run `! gh auth login`". The main agent relays that line and starts no watcher.
- **Otherwise it starts a background watcher agent** with a summary of the commit: its SHA, the branch, what the change did and why, and this machine's rules. Then it carries on with whatever the user asks next.
- **The watcher waits for CI** through `ci-watch.sh SHA`, then:
  - **green:** reports back that the run was ok;
  - **failed, and the fix is easy:** fixes it, pushes, and watches the new run;
  - **failed, and not easy:** reports back what failed, with a log excerpt and its diagnosis;
  - **superseded by a newer commit:** stops with one line;
  - **still running after the timeout:** reports that.
- **The main agent relays the report** when it arrives.

## Decisions taken

- **The watcher is a background subagent,** the in-session Agent tool, since it is the only mechanism that can both fix and report back into the session. The other options were a background script only (the main agent would then fix, and block) and a detached `claude -p` run (it couldn't notify the session).
- **It fixes in a worktree of its own, then pushes.** The main agent keeps editing the shared checkout meanwhile, so the watcher works in a separate git worktree based on the watched commit, commits through `commit.sh`, and pushes. If the branch moved in the meantime, the push is refused (`--force-with-lease --force-if-includes`), and the watcher reports instead of forcing. It always removes its worktree afterwards.
- **"Easy fix" means anything small,** shipped code included (the PAM module, the helper, the CLI, `install.sh`), as long as the relevant local tests pass.
- **The script lives in the skill's directory,** `.claude/skills/commit/ci-watch.sh` next to `commit.sh`, so the skill stays self-contained. It isn't shared through bcode.
- **The timeout is 30 minutes,** matching the longest job timeout in `ci.yml`, with room for a queued runner.
- **Without `gh`, it prints one line and starts no agent,** as described above.
- **The newest commit supersedes:** if the owner commits again while a watcher runs, only the latest commit on the branch is watched.
- **At most 2 fix rounds:** fix, push, watch, and once more at most. Then the watcher reports whatever still fails, with what it tried.

## The plan

**`ci-watch.sh`,** in `.claude/skills/commit/`:

- **`--preflight`:** checks quickly that `gh` is installed, that `gh auth status` passes, and that `origin` points at GitHub. Prints one line and exits with its own code when any of them fails.
- **`ci-watch.sh [SHA]`,** where the SHA defaults to `HEAD`:
  - waits up to about a minute for the commit's runs to appear (`gh run list --commit`);
  - polls until every run has finished, for at most 30 minutes;
  - checks along the way whether the commit is still the branch's tip on the remote;
  - prints each job's result, and for each failed job the tail of `gh run view --log-failed`, capped so the report stays short.
- **Exit codes:**
  - 0: all green;
  - 1: something failed;
  - 4: can't watch (no `gh`, not logged in, not GitHub);
  - 5: superseded by a newer commit;
  - 6: still running at the timeout.

**`SKILL.md`:**

- **Never block on CI:** the main agent never runs `gh run watch` and never polls CI itself.
- **After a successful push:** run the preflight. If it fails, relay its line and stop.
- **Otherwise:** start the watcher in the background from a prompt template kept in the skill's directory, say `watcher-prompt.md`. The template takes:
  - the SHA and the branch;
  - a summary of what the commit did;
  - the machine's rules: no installing or updating software on this machine (podman and pulling images are fine), commit only through the skill, never a plain `--force`, and machine-specific details stay out of the public repo.
- **Relay the report** when it arrives.
- **Skip all of this** when nothing was pushed: `commit.sh` exiting 1, 2 or 3, or with no remote.

**The watcher's instructions** (the template):

- **Wait:** run `ci-watch.sh SHA` in the background, without polling in between.
- **Act on the result:**
  - green: report "green for SHA";
  - superseded: report it in one line;
  - timeout: report "still running";
  - failed: diagnose from the excerpt and the full failed logs, and decide whether the fix is small.
- **To fix:**
  - `git worktree add` in a scratch location, at the watched commit;
  - make the fix there and run the relevant local tests (`cargo test`, and podman for the container suites);
  - commit through `commit.sh` from the worktree;
  - on a refused push, report and stop;
  - watch the new commit, at most 2 fix rounds in all.
- **Clean up:** always remove the worktree.
- **The report** names the commit or commits involved, the outcome, every file changed, and whether any of them is shipped code.

**Verification, once built:**

- run the script on a commit whose run passed;
- run it on `9b36a42`, whose container job failed on the permission errors, to check the failure summary;
- run the preflight with an empty gh configuration (`GH_CONFIG_DIR` pointing at an empty directory, no `GH_TOKEN`) for the graceful "not logged in" line;
- run it on a commit that is no longer the branch's tip, for exit 5;
- do one real round: a commit that breaks CI on purpose (on a scratch branch), the watcher fixing it, and the report arriving while the main agent works on something else.

## Remaining questions

- **How "newest supersedes" works.** The recommendation is that the watcher checks, before each step (fix, push, report), whether its commit is still the branch's tip on the remote, and stops with "superseded by `<sha>`" if not. The alternative is the main agent stopping the old watcher, which is more fragile. A fix the watcher pushes becomes the new tip itself, so the same check covers it.
- **Flagging fixes to shipped code.** "Easy fix" includes the PAM module, the helper and `install.sh`, which are security-critical. The recommendation is that the report always lists the files changed and marks shipped code explicitly, so the owner reviews it; the watcher pushes either way.
- **Which model runs the watcher.** Opus, like the main agent, writes the safer fixes, but costs more for what is mostly waiting. Sonnet watches cheaply but fixes less well. The lean is Opus, since it only works hard when something fails.
- **Reproducing a failure locally before pushing a fix.** That means `cargo test` and podman in the watcher's worktree. A worktree gets its own `target/`, so a cold build costs a few minutes; sharing the main checkout's `target/` means waiting on each other's build locks. The recommendation is the worktree's own `target/`, under the same machine rules as the main agent.
- **How a green report reaches the owner.** The suggestion is one line from the main agent at its next natural pause, such as "CI green for 6dab9fa". An unresolved failure comes with the watcher's summary and log excerpt.
