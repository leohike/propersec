# GitHub tests

A brief for adding GitHub Actions CI to propersec, written so an agent (or a person) can pick it up cold. The decisions below were made by the repo owner; the work itself hasn't started.

## Where to work

- On the branch `github`, in its own worktree, never in the main checkout (other work happens on `main` there). `wt switch -c github` creates both; the branch and its worktree already exist, clean, at `main`'s commit dae6f95, so `wt switch github` is enough. Use absolute paths into the worktree for every command.
- Pushing the `github` branch is allowed and expected: that is how the workflows get tested. Push, watch the run, fix, repeat until green.
- Don't merge into `main`, don't open a PR and don't push to `main`. The owner merges.

## Rules

- **Nothing gets installed or updated on the development machine:** no brew, flatpak, dnf/rpm-ostree, pip, npm, `cargo install`, rustup toolchains, or `curl | sh` installers. If something seems to need installing, stop and ask.
- **Containers and runners are fine:** pulling podman images and doing anything inside containers is allowed, and so is installing tools on the GitHub runner inside a workflow.
- **Commits only through the commit script,** `.claude/skills/commit/commit.sh`, with the message on stdin and the worktree as the working directory:
  - it stages everything, adds the only attribution trailer itself, and pushes with `--force-with-lease --force-if-includes`, setting the upstream on the first push;
  - never add `Co-Authored-By:` or `Assisted-by:` lines by hand;
  - never use plain `--force`;
  - if the push is rejected (exit 3), stop and report;
  - check `git status` before committing, so no build output or scratch files go in.
- **Markdown in this repo:** never hard-wrap prose (one line per paragraph or bullet), and never number headings or list items.

## The repo

- **Workspace:** a Cargo workspace at the root, edition 2024, `rust-version = "1.98"`, members `products/*/crates/*`, with `Cargo.lock` committed. The just recipes live in `products/pin/properpin.just`, included from the root `justfile` as `mod properpin`.
- **Build needs:**
  - Rust 1.98 and a C linker (gcc);
  - libxcrypt with its development symlink `libcrypt.so` (Fedora `libxcrypt-devel`, Debian/Ubuntu `libcrypt-dev`);
  - `libpam.so.0` at run time; it is linked by its runtime name, so no PAM development package is needed.
- **Tests:** the stack tests use the real libpam through `pam_start_confdir`, which needs Linux-PAM 1.4 or later, plus `pam_permit.so` and `pam_deny.so`. Hashing is yescrypt through libxcrypt. The stack tests build the module themselves with `cargo build`, which is expected. Fedora 44 ships Rust 1.98.1 and Linux-PAM 1.7.2, matching the local setup.
- **The system test,** `just properpin podman`, which takes about a minute locally, is two commands:
  - `podman build --quiet --ignorefile products/pin/testing/podman/Containerfile.containerignore -f products/pin/testing/podman/Containerfile -t properpin-systest .`
  - `podman run --rm --network=none properpin-systest`

  Inside the container it runs its scenarios (25 as of the setuid helper) as root: it installs properpin with `install.sh`, listens on `/dev/log`, and runs attempts through the setuid `unix_chkpwd`. The Containerfile uses `RUN --mount=type=cache`, which needs a buildah/podman recent enough to support it.
- **Read first:** `CLAUDE.md`, the root `Cargo.toml`, `products/pin/properpin.just`, `products/pin/docs/README.md`, `products/pin/testing/podman/Containerfile`, and `docs/plan.md`.

## What CI should do

**Triggers:** every push to any branch, and pull requests.

**Jobs.** There is no lint job: clippy and fmt stay local, by the owner's choice.

- **Tests:** `cargo test --workspace --locked` in a `fedora:44` container job, matching the local setup.
- **Podman system test:**
  - build the Containerfile and run it on an Ubuntu runner, whose podman should handle it;
  - check that the runner's podman supports `--ignorefile` and cache mounts. If it doesn't, find a workable approach and say why. Only fall back to `docker build` on the same Containerfile if podman really can't.
  - `just` may not be on the runner, so call the two podman commands directly, or install `just` on the runner.
- **Dependency audit:**
  - run `cargo-deny` and `cargo-audit`, installed on the runner only and pinned by SHA or version;
  - known security advisories fail the job; licences, bans, duplicates and sources are warnings only, for now;
  - add a `deny.toml` at the repo root configured that way, with a short comment saying so;
  - the workspace crates have `publish = false` and no licence field, and that must not cause hard failures, for example via `private.ignore = true`.
- **Toolchain check:**
  - build and test with exactly Rust 1.98, the declared `rust-version`, not just whatever Fedora ships;
  - if Ubuntu's Linux-PAM is too old for `pam_start_confdir`, run this job in `fedora:44` with Rust 1.98 installed through rustup inside the container. That's the runner, not the development machine, so it's allowed.

**Hardening:**

- **Permissions:** `permissions: contents: read` at the workflow level, and no write access anywhere.
- **Pinned actions:**
  - every third-party action is pinned to a full commit SHA, with a `# vX.Y.Z` comment;
  - look the SHAs up (`gh api`, `git ls-remote`) and never invent them.
- **Builds and checkout:** `--locked` on every cargo command, and `persist-credentials: false` on checkout.
- **Runs:** a concurrency group that cancels superseded runs on the same ref, and a sensible `timeout-minutes` on every job.
- **Dependabot:** a `.github/dependabot.yml` that bumps GitHub Actions weekly. Cargo too, if it seems right; say which you chose.

**Caching:** cache the cargo registry and `target/` where it clearly helps (`actions/cache` or `Swatinem/rust-cache`, pinned by SHA), and keep it simple.

## Watching runs: gh and a token

- **What works without logging in:** pushing goes over SSH and doesn't involve `gh`. Because the repo is public, run status can be read without logging in through the REST API (`curl https://api.github.com/repos/leohike/propersec/actions/runs?branch=github`, about 60 requests an hour).
- **What needs a login:** job logs need a logged-in user even on public repos, and `gh` refuses to run until logged in. Without a login, a failing job can be seen but not diagnosed.
- **The token:** a fine-grained personal access token. Create it under Settings → Developer settings → Personal access tokens → Fine-grained tokens:
  - Repository access: **Only select repositories** → `propersec`;
  - repository permissions: **Actions: read** (read and write to also re-run or cancel runs), **Contents: read**, and **Metadata: read**, which is always included;
  - no Workflows or Contents write, since pushes go over SSH;
  - no Administration or Secrets: anything running as the user, agents included, can use the token;
  - an expiry of 30 to 90 days.

  Log in with `gh auth login --with-token`, paste the token, and check with `gh auth status`.
- **What works with a fine-grained token:** `gh run list --branch github`, `gh run watch` and `gh run view --log-failed` use the Actions API. Fine-grained tokens can't use the Checks API, so commands built on it, such as `gh pr checks`, may fail.
- **If `gh` isn't logged in:** finish with the workflows written and sanity-checked locally, by running the same build and test commands inside a `fedora:44` podman container, and say so. Never ask for credentials.

Sources: [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens), [Permissions required for fine-grained personal access tokens](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).

## Docs to update

- **The product README:** add a short CI section to `products/pin/docs/README.md` saying what runs, what blocks, and where to look.
- **The plan:** update the CI and dependency-checks rows in `docs/plan.md` to reflect what is done.

## Report at the end

- the worktree and branch;
- the commits made, with hashes and subjects;
- the final run URLs, with each job's status and runtime;
- every action used, with its pinned SHA and version;
- anything that didn't work or was skipped, and why;
- anything the owner has to decide.
