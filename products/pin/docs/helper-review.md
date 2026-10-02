# Reviewing properpin-helper

A checklist for reviewing the setuid helper: every hazard a setuid program faces, what `properpin-helper` does about it, where in the code, and which test shows it. It is meant to be read next to the code, top to bottom, in one sitting. What is still open is in `docs/concerns.md` at the repo root.

**The shape, in one paragraph.** The helper is installed `properpin:properpin 6755`: it runs as the `properpin` account and group, with its caller's real uid. It reads the PIN hashes in `/etc/properpin/users` (`root:properpin 0640`, so it can read them and not change them) and keeps every user's counts in `/run/properpin` (its own, `0700`). Its caller is the PAM module, the CLI's `status`, or anything else the user runs, so every caller is treated as hostile. It answers with an exit code; only `status` prints, and only about the caller. The code is `crates/helper`: `main.rs` (the setuid entry point), `secure.rs` (all of its `unsafe` code), `lib.rs` (the decisions, with `#![forbid(unsafe_code)]`) and `chkpwd.rs` (`unix_chkpwd`).

## Who is asking

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| The caller claims to be someone else | The caller is always the real uid from the kernel (`getuid`), turned into a name through the passwd database. No argument names a user | `main.rs`, `run` | `another_user_gets_nothing` (container): bob passing `alice` is refused |
| A crafted user name reaches a path | `UserFiles::new` refuses empty names, `.`, `..` and names with `/`; the passwd database is the only source anyway | `sys/src/files.rs` | `a_bad_user_name_is_refused_before_any_file` |
| Root calls it | Refused: root has no lock screen, and a root caller would have every user's name to choose from | `main.rs`, `run` | `status_shows_your_own_pin` (container), through the CLI and the helper directly |
| The caller picks the files | Fixed locations. The `--dev-*` options that replace them are accepted only when `AT_SECURE` says the program wasn't started with elevated rights, and then it has no more rights than its caller | `main.rs`, `Options` and `run`; `secure.rs`, `elevated` | `dev_options_are_refused_under_setuid` (container), which fails when the check is disabled |

## What it inherits

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| Closed stdin, stdout or stderr, so a file it opens lands on 0, 1 or 2 | Each is reopened on `/dev/null` if closed | `secure.rs`, `start_clean` | `a_poisoned_start_changes_nothing` (local and container) |
| Open files left by the caller | All descriptors from 3 up are closed (`close_range`) | `secure.rs`, `start_clean` | Same; nothing shows it directly, see `docs/concerns.md` |
| Ignored, caught or blocked signals | Every signal back to its default and none blocked; SIGPIPE ignored, so a closed pipe is an error, not a death | `secure.rs`, `start_clean` | Not directly |
| The environment (`LD_PRELOAD`, locale, `TZ`, `RUST_BACKTRACE`) | The loader and glibc ignore the dangerous ones in setuid mode; the helper clears the environment, never reads it, starts `unix_chkpwd` with none, and its panic hook aborts without printing (the default one reads `RUST_BACKTRACE`) | `secure.rs`, `start_clean`; `main.rs`, `main`; `chkpwd.rs` | `a_poisoned_start_changes_nothing` (local and container) |
| The umask and the working directory | umask `077`, working directory `/` | `secure.rs`, `start_clean` | Not directly |
| Resource limits | Not reset. Any limit can only make it fail, and it fails before the hash is checked or after the failure is saved, because the failure is saved first | `core/src/attempt.rs`, `check` | `a_failure_is_saved_before_the_hash_is_checked`; no limit-specific test, see `docs/concerns.md` |
| Being traced or dumped by the caller | The kernel makes a setuid process non-dumpable and refuses its caller `ptrace` | The kernel | Not tested |

## Input and output

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| Too much input, or input that grows a buffer | Reads into one buffer of 513 bytes, allocated once; anything longer comes back too long to be a PIN or a PAM response. Wiped on exit | `lib.rs`, `read_input` | `input_is_read_up_to_the_limit_only`, `input_that_cannot_be_a_pin_is_refused_and_not_counted` |
| NUL bytes, invalid UTF-8, empty input | Unusable, never hashed, never counted | `core/src/attempt.rs`, `usable_input` | Same, and `unusable_input_is_never_counted` |
| Arguments | Exactly one request word and `--dev-*` pairs; anything else is refused with exit 2 | `main.rs`, `Options::parse` | `anything_unexpected_on_the_command_line_is_refused` |
| A terminal on stdin | Refused, like `unix_chkpwd`. This only discourages typing at it by hand | `main.rs`, `run` | Not tested (needs a terminal) |
| Secrets in the output or the log | The exit code is the answer. Log lines carry the user name and the verdict, never input. `status` prints settings and counts for the caller only | `lib.rs`, `serve`, `status` | `status_shows_your_own_pin` (container) |
| A panic halfway | Aborts at once, without unwinding or printing. A panic during a check comes after the failure was saved | `main.rs`, `main` | Not directly |

## Files

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| A symlink or a non-regular file | Opened with `O_NOFOLLOW`, checked on the open file, so the file checked is the file read | `sys/src/files.rs`, `read_regular_file` | `a_symlink_is_never_followed`, `a_symlinked_user_file` (container) |
| A user file someone else could change or read | Must be owned by root, not writable by group or others, not readable by others | `sys/src/files.rs`, `read_trusted` | `untrusted_files_are_refused`, three container scenarios |
| A state directory others can reach | Must be a directory owned by the account the helper runs as, mode `0700` | `sys/src/files.rs`, `private_run_dir` | `a_shared_run_dir_is_refused`, `a_run_dir_owned_by_someone_else_is_refused`, `a_shared_runtime_directory` (container) |
| The user resets or reads their counts | They can't reach `/run/properpin` at all | install.sh; `sys/src/files.rs` | `the_user_cannot_reach_the_files` (container) |
| A half-written state | Written to a temporary file in the same directory and renamed over, under an exclusive lock with a one-second timeout | `sys/src/files.rs`, `save_state`, `lock` | `state_round_trips_under_the_lock`, `a_held_lock_times_out_instead_of_hanging`, `concurrent_wrong_pins_are_all_counted` (container) |
| One user's attempts affecting another's | One state file and one lock per uid | `sys/src/files.rs` | `each_user_has_their_own_state`, `each_caller_gets_only_their_own_pin_and_counts` |

## Decisions

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| A guess checked but never counted (a kill at the right moment) | The failure is saved before the hash is checked and taken back on a match | `core/src/attempt.rs`, `check` | `every_check_happens_with_its_attempt_already_counted` |
| Anything the user runs arming the PIN, to reset the failures | `arm` checks the password through `unix_chkpwd` first, and refuses an empty one | `lib.rs`, `arm_pin`; `chkpwd.rs` | `a_wrong_password_never_arms`, `arming_after_failures_needs_the_password_too`, `arming_checks_the_password_itself` (container, real `unix_chkpwd`), which fails when the check is removed |
| `unix_chkpwd` answering about someone else | It answers only about the user its caller really is; the helper keeps its caller's real uid, so the two agree | `chkpwd.rs` | `arming_checks_the_password_itself` (container) |
| The hash compared in a way that leaks timing | libxcrypt hashes; the result is compared in constant time where libxcrypt wrote it | `sys/src/crypt.rs` | `hashes_and_verifies` |

## The caller's side: the PAM module

| Hazard | What the module does | Where | Tested by |
|---|---|---|---|
| The helper quits without reading, and the write raises SIGPIPE in the lock screen | The module keeps its own copy of the pipe's read end open until it has written, as pam_unix does | `pam/src/run.rs`, `ask_helper` | `a_broken_helper_fails_closed` ("quits without reading") |
| The host ignores SIGCHLD, so the exit status is lost | SIGCHLD set to its default while the helper runs, then put back | `pam/src/pam.rs`, `DefaultSigchld` | Not directly; see `docs/concerns.md` |
| The lock screen's environment or files reaching the helper | An empty environment, `/` as working directory, the pipe as stdin, `/dev/null` for output; std's pipes are close-on-exec | `pam/src/run.rs`, `ask_helper` | Indirectly |
| A hung helper hangs the lock screen | Killed after 10 seconds, and the PIN refused | `pam/src/run.rs`, `wait` | Not tested (would take 10 seconds); see `docs/concerns.md` |
| The helper missing, killed, or answering oddly | Every answer but 0 refuses, and the password still works | `pam/src/run.rs`, `run` | `a_broken_helper_fails_closed`, `a_missing_helper_fails_closed` (container) |

## Installed permissions

`install.sh check` verifies each of these, and the container runs it after installing.

| Path | Owner and mode | Why |
|---|---|---|
| `/usr/local/libexec/properpin/properpin-helper` | `properpin:properpin 6755` | Setuid for the counts, setgid for reading hash files. The account owns its own binary, an open decision in `docs/concerns.md` |
| `/etc/properpin/users/` | `root:properpin 0750` | The user can't list who has a PIN |
| `/etc/properpin/users/<user>` | `root:properpin 0640` | Root writes it (`sudo properpin set`), the helper reads it, nobody else |
| `/run/properpin/` | `properpin:properpin 0700` | The counts, out of every user's reach |
