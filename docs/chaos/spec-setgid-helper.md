# Spec: run screenlock-pin-helper as a group, not an account

A self-contained spec for one change to screenlock-pin, written on 2026-10-03 to be implemented as is. It replaces the `screenlock-pin` system account with a `screenlock-pin` system group: the helper becomes setgid only and owned by root. Everything an implementer needs is here; the discussion behind it is summarised in Why below.

**Status: implemented on 2026-10-03.** Deviations, each recorded in `docs/chaos/concerns.md`: `refuse_old_layout` was removed rather than adapted, since no earlier layout was ever installed; `check` on the real system requires root instead of printing that gshadow wasn't verified; the caller can't change the running helper's resource limits after all (`prlimit` also checks group ids), so that cost in Why doesn't apply; planted lock files are described, with a fix, in `docs/chaos/planted-lock-dos.md`.

## Rules for whoever implements this

- Work in the propersec repo, product `products/pin`. Read `CLAUDE.md` at the repo root first: no numbered headings or lists in markdown, no hard-wrapped prose, commit only when asked and only through the commit skill.
- Nothing may be installed or changed on the development machine. Building, `cargo test`, and the podman container (`just screenlock-pin podman`) are the only places this runs. Pulling images is fine.
- Match the surrounding code: its comment density, naming and idiom. `unsafe` stays confined to `crates/helper/src/secure.rs`, `crates/pam/src/pam.rs` and the FFI files that already allow it.
- Whatever turns out to be out of reach, or is a new small worry, goes into `docs/chaos/concerns.md` rather than being silently skipped.

## Why

Today (commit `d62f825`) the helper is `screenlock-pin:screenlock-pin 6755`: setuid and setgid to a `screenlock-pin` system account. The account owns its own binary, so an attacker who exploits a helper bug once could rewrite the binary and capture every password sent to `arm` from then on. That is the first decision listed in `docs/chaos/concerns.md`.

A setuid program always runs as its file's owner, so "owned by root, runs as screenlock-pin" is impossible with setuid. A file's group is separate from its owner, though: a root-owned file that is setgid to `screenlock-pin` runs with the `screenlock-pin` group, while only root can change it. The helper keeps its caller's user id, which it already uses to know who is asking. This is the classic pattern for such helpers: Debian's `unix_chkpwd` is setgid `shadow`, `crontab` setgid `crontab`, `write` setgid `tty`.

What this gains:

- **The binary can't be rewritten** by anything short of root, with no special attribute to remember.
- **There is no account at all**, only a group with no members and a locked password, so nothing can ever log in as screenlock-pin.
- **Users are separated from each other** inside `/run/screenlock-pin`: each user's counts file belongs to that user, mode 0600, in a sticky directory, so an exploited helper run by bob can't read, delete or replace alice's counts. Today every counts file belongs to the one account.

What it costs: counts files belong to the user they describe, which looks odd (alice owns a file she can't reach, since she can't enter the directory); the caller can change the running helper's resource limits, which, like any limit, can only make it fail after the attempt is counted; and a user could plant a counts file in another user's name before that user's first attempt of the boot, which this spec closes with an ownership check.

## The target layout

| Path | Owner, group, mode | Notes |
|---|---|---|
| `/usr/local/libexec/screenlock-pin/screenlock-pin-helper` | `root:screenlock-pin 2755` | setgid only; was `screenlock-pin:screenlock-pin 6755` |
| `/etc/screenlock-pin/` | `root:root 0755` | unchanged |
| `/etc/screenlock-pin/users/` | `root:screenlock-pin 0750` | unchanged |
| `/etc/screenlock-pin/users/<user>` | `root:screenlock-pin 0640` | unchanged |
| `/run/screenlock-pin/` | `root:screenlock-pin 1770` | was `screenlock-pin:screenlock-pin 0700`; sticky, group-writable |
| `/run/screenlock-pin/<uid>.state`, `<uid>.lock` | `<uid>:screenlock-pin 0600` | created by the helper running as that user; was owned by the account |
| `/run/screenlock-pin/.<uid>.*` | `<uid>:screenlock-pin 0600` | temporary files before the rename, as today |
| `/etc/sysusers.d/screenlock-pin.conf` | `root:root 0644` | `g screenlock-pin -` only; was `u screenlock-pin - ...` |
| `/etc/tmpfiles.d/screenlock-pin.conf` | `root:root 0644` | `d /run/screenlock-pin 1770 root screenlock-pin -` |

The group has no members, and its password in `/etc/gshadow` is locked (`!` or `*`), so the only way any process gets the group is running the helper. No `screenlock-pin` user exists.

## Code changes

### screenlock-pin-sys (`crates/sys`)

- **`UserFiles::with_runtime`** takes the directory, the uid that must own it, and the gid that must be its group: `with_runtime(dir, owner, group)`. In production the owner is root and the group is the helper's effective gid.
- **The runtime directory check** (`private_run_dir`, rename it to something like `trusted_run_dir`) requires: a directory, not a symlink, owned by `owner`, group `group`, and mode exactly `1770` (`mode & 0o7777 == 0o1770`). Anything else is refused with a message naming what is wrong. This replaces "owned by the account, mode & 077 == 0".
- **The lock file must belong to the caller.** After opening `<uid>.lock` (still `O_NOFOLLOW`, created `0600` if missing), check on the open file that it is a regular file owned by the `uid` the `UserFiles` was built for; otherwise refuse with "owned by uid N, not M". Every path that writes state takes the lock first, so this catches a lock file planted by another user. With `fs.protected_regular=2` the kernel may already refuse the open; either way the attempt is refused.
- **A state file that isn't the caller's reads as no state.** `load_state` checks, on the open file, that it is owned by `uid`; if not, it returns `None` (no state means the password is required, which is the safe reading). The lock check above is what produces the clear log line.
- **Add `current_gid` and `current_egid`** next to `current_uid` and `current_euid` in `accounts.rs` (nix has safe wrappers).
- `save_state`, the temporary-file prefix and the atomic rename stay as they are: in a sticky directory a rename may replace a file only if the caller owns it, which is exactly the user's own state file.

### screenlock-pin-helper (`crates/helper`)

- **`Places`** gains the runtime directory's group: `run_owner` becomes the uid that must own the directory, `run_group` the gid that must be its group. Production values in `main.rs`: `etc_owner: 0`, `run_owner: 0`, `run_group: current_egid()`. A misinstalled helper without setgid then has the caller's group, which doesn't match the directory, and refuses: it fails closed, as today's `run_owner: current_euid()` does.
- **Dev options**: `--dev-owner` keeps its meaning (owner of the files under `--dev-etc`) and also becomes the owner the `--dev-run` directory must have; `run_group` stays `current_egid()`.
- **A second, independent guard on the dev options.** Today they are refused when `AT_SECURE` is set. Also refuse them unless the real and effective user ids are equal and the real and effective group ids are equal. Put the decision in a pure function in `lib.rs`, for example `dev_options_allowed(at_secure: bool, uid: u32, euid: u32, gid: u32, egid: u32) -> bool`, called from `main.rs` with the real values, so it can be unit tested by truth table: allowed only when `at_secure` is false and both pairs match.
- **Wording**: doc comments in `lib.rs`, `main.rs` and `secure.rs` that say "setuid to the screenlock-pin account" become setgid to the screenlock-pin group. `secure.rs` already covers what the kernel does for any elevated start; setgid triggers it the same way (`AT_SECURE`, non-dumpable).

### pam_screenlock_pin and screenlock-pin-cli

No behaviour change. Update wording that says "setuid helper" where it refers to screenlock-pin-helper (the module's `lib.rs`, the CLI's doc comment). The CLI's `--group` default stays `screenlock-pin`.

## install.sh

- **Options**: replace the test-only `--account USER` with `--helper-group GROUP` (default `screenlock-pin`). Fake-root tests pass the test user's primary group.
- **`sysusers_conf`** writes `g $helper_group -`. **`tmpfiles_conf`** writes `d $run_dir 1770 $owner $helper_group -`.
- **Creating the group**, on the real system only, if it doesn't exist: `systemd-sysusers "$sysusers"` where available, else `groupadd --system "$helper_group"`. In a fake root the group must already exist. No user is ever created.
- **`install`**: helper `put` with mode `2755` and owner `$owner:$helper_group` (chown before chmod, as `put` already does, since chown clears the setgid bit); `/run/screenlock-pin` created `1770 $owner:$helper_group`; the users directory `0750 $owner:$helper_group`; `refuse_old_layout` compares user files' group with `$helper_group`.
- **`check`** expects those modes and owners, compares both config files with what `install` writes, and, on the real system only:
  - the group exists, has no members (the fourth field of `getent group`), and is nobody's primary group (no line in `getent passwd` with its gid);
  - its gshadow password starts with `!` or `*`; reading gshadow needs root, so when `check` runs unprivileged it prints that this wasn't verified instead of failing.
- **`uninstall`** removes the helper, the module, the command, both config files and `/run/screenlock-pin`, keeps `/etc/screenlock-pin` and the group (the kept PIN files belong to it), and prints `rm -r /etc/screenlock-pin && groupdel screenlock-pin` for removing both.
- Installs of the account-based layout are not migrated: nothing is deployed. Note that in `docs/chaos/concerns.md`.

## Tests

### Local, instant

- **screenlock-pin-sys `files.rs`**: the runtime directory refused when its mode is `0700`, `0770` (no sticky bit) or `1777`, when its group is wrong, and when its owner is wrong; accepted at `1770`. A lock file not owned by the caller refused: build the `UserFiles` for `current_uid() + 1`, let the test (as itself) create the lock file, and expect the refusal, since a test can't chown files to another user. A state file not owned by the caller reads as `None`, the same way.
- **screenlock-pin-helper `lib.rs`**: the `dev_options_allowed` truth table; the existing tests with the sandbox's run directory at `1770` and the test user's group.
- **screenlock-pin-helper `tests/helper.rs`, pam `tests/stack.rs`, cli `tests/cli.rs`**: sandbox run directories at `1770`: create them, then `set_permissions` to `1770` explicitly, because the umask (usually `022`) would strip the group's write bit from a `mkdir` with that mode.
- **systest `tests/install.rs`**: `--helper-group` instead of `--account`; the helper `0o2755`; `/run/screenlock-pin` `0o1770`; sysusers holds `g <group> -`; tmpfiles holds `d /run/screenlock-pin 1770 ...`; `check` reports a helper at `4755` or `6755`, a run directory at `0700`, and edited config files.

### Container (`crates/systest/src/main.rs`)

Adapt the existing 25 scenarios: `reset` restores `/run/screenlock-pin` to `root:screenlock-pin 1770`, user files keep group `screenlock-pin`, the uninstall scenario expects the group to remain and checks no `screenlock-pin` user exists. Rename "--dev options are refused under setuid" to "...under setgid". Add:

- **The group can't change the helper.** As bob with group `screenlock-pin` (spawn with `uid(bob)` and `gid(screenlock-pin)`, which stands in for an exploited helper), appending to, `chmod`-ing, renaming and deleting the helper all fail, and its bytes are unchanged.
- **One user's helper can't touch another's counts.** After alice has a counts file, as bob with group `screenlock-pin`: reading, overwriting, deleting and renaming `/run/screenlock-pin/<alice uid>.state` all fail, and alice's next PIN attempt still sees her failures.
- **A counts file planted in another user's name is refused.** Before alice's first attempt of the scenario, as bob with group `screenlock-pin`, create `<alice uid>.lock` mode `0666` and an armed `<alice uid>.state`. alice's PIN is refused and the log names the lock file's wrong owner; her password still works. `reset` removes both.
- **The group stays empty and locked.** `install.sh check` passes; after `usermod -aG screenlock-pin bob` it fails naming the member; after removing him it passes again. With gshadow's password field set to empty it fails; restored, it passes.
- **No account exists**: `getent passwd screenlock-pin` finds nothing after install.

### Checked by breaking things on purpose

Run each once, see the named test fail, restore, and record the result in the README's container section:

- the sticky bit dropped from the run directory (in `install.sh` and the tmpfiles rule, and the directory check relaxed to accept it): "one user's helper can't touch another's counts" fails;
- the lock file ownership check removed: "a counts file planted in another user's name" fails on its log assertion;
- either half of `dev_options_allowed` removed: its unit test fails, while the container's `--dev` scenario still passes, which shows the two guards are independent.

## Docs to update

- `products/pin/docs/README.md`: the files table, the crate row and The helper section (setgid, root-owned, a group with no members), the container scenarios and the mutations, the install paragraph (the group, `groupadd` fallback, uninstall keeps the group). Keep the lesson about setuid not changing the group; it explains why the group is the identity now.
- `products/pin/docs/helper-review.md`: the shape paragraph, the "Who is asking" and "Files" rows (sticky directory, ownership checks, the two dev guards), the installed permissions table.
- `docs/chaos/concerns.md`: resolve the first decision (say what was chosen and why, keep it short); drop or adjust entries that assumed the account (the NSS entry still holds; the "SELinux unknown" entry now concerns a setgid helper); add the caller's `prlimit` on the running helper, the counts files owned by their users, `fs.protected_regular`, and the account-based layout not being migrated.
- `docs/chaos/threat-insider-hash-leak.md`: the status line says "dedicated account"; make it "dedicated group".
- `docs/chaos/plan.md`: nothing structural; check no row still mentions the account.

## Not in this change

- Mixing the password into the PIN hash (the pepper), which is a separate plan row.
- Checking that `/run/screenlock-pin` is a memory filesystem; it is in `docs/chaos/concerns.md`.
- The repeated-access fix and the 100 ms floor.

## Done when

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass;
- `just screenlock-pin podman` passes every scenario, old and new;
- the three deliberate breakages above were each seen to fail and were restored;
- `grep -rn "screenlock-pin account\|u screenlock-pin\|--account" products docs` finds nothing stale;
- the docs listed above are updated.
