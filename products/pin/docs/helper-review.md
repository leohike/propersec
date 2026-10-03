# Reviewing properpin-helper

A checklist for reviewing the setgid helper: every hazard a program with more rights than its caller faces, what `properpin-helper` does about it, where in the code, and which test shows it. It is meant to be read next to the code, top to bottom, in one sitting. What is still open is in `docs/concerns.md` at the repo root.

**The shape, in one paragraph.** The helper is installed `root:properpin 2755`: it runs as its caller, with the `properpin` group added. The group has no members, no account goes with it, and its password is locked, so running the helper is the only way to get it, and only root can change the binary. It reads the PIN hashes in `/etc/properpin/users` (`root:properpin 0640`, so it can read them and not change them) and keeps every user's counts in `/run/properpin` (`root:properpin 1770`: only the group can enter, and the sticky bit lets only a file's owner replace or delete it), each user's files owned by that user. Its caller is the PAM module, the CLI's `status`, or anything else the user runs, so every caller is treated as hostile. It answers with an exit code; only `status` prints, and only about the caller. The code is `crates/helper`: `main.rs` (the setgid entry point), `secure.rs` (all of its `unsafe` code), `lib.rs` (the decisions, with `#![forbid(unsafe_code)]`) and `chkpwd.rs` (`unix_chkpwd`).

## Who is asking

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| The caller claims to be someone else | The caller is always the real uid from the kernel (`getuid`), turned into a name through the passwd database. No argument names a user | `main.rs`, `run` | `another_user_gets_nothing` (container): bob passing `alice` is refused |
| A crafted user name reaches a path | `UserFiles::new` refuses empty names, `.`, `..` and names with `/`; the passwd database is the only source anyway | `sys/src/files.rs` | `a_bad_user_name_is_refused_before_any_file` |
| Root calls it | Refused: root has no lock screen, and a root caller would have every user's name to choose from | `main.rs`, `run` | `status_shows_your_own_pin` (container), through the CLI and the helper directly |
| The caller picks the files | Fixed locations. The `--dev-*` options that replace them are accepted only when two independent checks agree the program runs without elevated rights: `AT_SECURE` is clear, and the real and effective user and group ids are equal. Then it has no more rights than its caller | `lib.rs`, `dev_options_allowed`; `main.rs`, `Options` and `run`; `secure.rs`, `elevated` | `dev_options_are_refused_under_setgid` (container), which fails when the `AT_SECURE` check is disabled and still passes with either check alone; `dev_options_need_both_guards_to_agree`, the truth table |

## What it inherits

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| Closed stdin, stdout or stderr, so a file it opens lands on 0, 1 or 2 | Each is reopened on `/dev/null` if closed | `secure.rs`, `start_clean` | `a_poisoned_start_changes_nothing` (local and container) |
| Open files left by the caller | All descriptors from 3 up are closed (`close_range`) | `secure.rs`, `start_clean` | Same; nothing shows it directly, see `docs/concerns.md` |
| Ignored, caught or blocked signals | Every signal back to its default and none blocked; SIGPIPE ignored, so a closed pipe is an error, not a death | `secure.rs`, `start_clean` | Not directly |
| The environment (`LD_PRELOAD`, locale, `TZ`, `RUST_BACKTRACE`) | The loader and glibc ignore the dangerous ones in secure-execution mode, which setgid triggers like setuid; the helper clears the environment, never reads it, starts `unix_chkpwd` with none, and its panic hook aborts without printing (the default one reads `RUST_BACKTRACE`) | `secure.rs`, `start_clean`; `main.rs`, `main`; `chkpwd.rs` | `a_poisoned_start_changes_nothing` (local and container) |
| The umask and the working directory | umask `077`, working directory `/` | `secure.rs`, `start_clean` | Not directly |
| Resource limits | Not reset. Limits set before the start are inherited; the caller can't change them on the running helper, because `prlimit` on another process also requires matching group ids, and the helper's effective group differs. Any limit can only make it fail, and it fails before the hash is checked or after the failure is saved, because the failure is saved first | `core/src/attempt.rs`, `check` | `a_failure_is_saved_before_the_hash_is_checked`; no limit-specific test, see `docs/concerns.md` |
| Being traced or dumped by the caller | The kernel makes a setgid process non-dumpable and refuses its caller `ptrace` | The kernel | Not tested |
| Signals from the caller | It keeps the caller's uid, so the caller may kill or stop it, as with `unix_chkpwd`. A kill comes after the failure was saved; a stopped helper holds only the caller's own lock | `core/src/attempt.rs`, `check` | `every_check_happens_with_its_attempt_already_counted` |

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
| A state directory others can reach, or without the sticky bit | Must be a directory, not a symlink, owned by root, with the group the helper runs with, mode exactly `1770`. A helper installed without its setgid bit runs with the caller's group, which doesn't match, and refuses | `sys/src/files.rs`, `trusted_run_dir` | `a_run_dir_with_any_other_mode_is_refused`, `a_run_dir_with_another_owner_or_group_is_refused`, `a_symlinked_run_dir_is_refused`, `a_shared_runtime_directory` (container) |
| The user resets or reads their counts | They can't enter `/run/properpin` at all | install.sh; `sys/src/files.rs` | `the_user_cannot_reach_the_files` (container) |
| One user's run of the helper, exploited, touching another's counts | Each user's state and lock files belong to that user, mode `0600`, and the directory is sticky, so another user's process can't read, write, rename or delete them | `sys/src/files.rs`; install.sh | `one_users_helper_cannot_touch_anothers_counts` (container), which fails without the sticky bit |
| A lock or state file planted in another user's name | The lock file must be a regular file owned by the caller, checked on the open file, or the attempt is refused with a log line naming its owner; a state file not owned by the caller reads as no state, which requires the password. A planted lock file blocks that user's PIN until reboot, see `docs/planted-lock-dos.md` | `sys/src/files.rs`, `lock` and `load_state` | `a_lock_file_planted_by_someone_else_is_refused`, `a_state_file_planted_by_someone_else_reads_as_none`, `planted_counts_are_refused` (container) |
| A half-written state | Written to a temporary file in the same directory and renamed over, under an exclusive lock with a one-second timeout | `sys/src/files.rs`, `save_state`, `lock` | `state_round_trips_under_the_lock`, `a_held_lock_times_out_instead_of_hanging`, `concurrent_wrong_pins_are_all_counted` (container) |
| One user's attempts affecting another's | One state file and one lock per uid | `sys/src/files.rs` | `each_user_has_their_own_state`, `each_caller_gets_only_their_own_pin_and_counts` |
| A reboot wiping the failure budget | The budget is in `/var/lib/properpin`, checked like `/run/properpin` (`1770`, root's, the helper's group), written to a temporary file, synced, renamed, and the directory synced | `sys/src/files.rs`, `save_budget` | `unforgiven_guesses_disable_the_pin` (container), which fails with the budget in `/run` |
| A damaged, foreign or open budget read as a fresh one | Missing means empty; anything else that isn't a private budget owned by the caller and parsing exactly is an error, so the PIN is refused until `set` starts it over | `sys/src/files.rs`, `load_budget`; `core/src/budget.rs`, `parse` | `a_budget_that_cannot_be_trusted_is_an_error_not_an_empty_budget`, `a_damaged_or_planted_budget` (container) |

## Decisions

| Hazard | What the helper does | Where | Tested by |
|---|---|---|---|
| A guess checked but never counted (a kill at the right moment) | The failure is saved before the hash is checked and taken back on a match; the budget records every input before anything is decided, the same way | `core/src/attempt.rs`, `check` | `every_check_happens_with_its_attempt_already_counted`, `a_failure_is_saved_before_the_hash_is_checked` |
| Slow guessing across many arming periods | Every failure nobody forgave within 45 s of a correct PIN or 90 s of the correct password is concerning; 10 a day, 20 a week or 100 since the PIN was set disable it, across reboots | `core/src/budget.rs`; `core/src/attempt.rs` | `a_slow_attacker_is_stopped` and `nothing_is_ever_lost` (proptests), `guesses_the_user_never_forgives_disable_the_pin`, `the_slow_attack_is_stopped` (container) |
| Anything the user runs forgiving failures | Only a correct PIN, through the hash, or `arm`, after `unix_chkpwd`, forgives; `status` judges in memory and writes nothing | `core/src/attempt.rs`; `lib.rs`, `arm_pin`, `status` | `status_needs_no_input_and_prints_the_rules`, `typos_are_forgiven` (container) |
| The clock moved to hide failures | Failures stamped over a minute in the future are concerning at once; concerning ones stay until the clock passes them; the total never goes down | `core/src/budget.rs`, `judge` | `a_clock_set_back_neither_hides_nor_delays_failures` |
| A flood of inputs growing the budget | At most 50 waiting failures (the oldest is judged concerning beyond that) and 200 concerning ones; the total keeps counting | `core/src/budget.rs` | `a_flood_of_failures_is_judged_rather_than_dropped` |
| Anything the user runs arming the PIN, to reset the failures | `arm` checks the password through `unix_chkpwd` first, and refuses an empty one | `lib.rs`, `arm_pin`; `chkpwd.rs` | `a_wrong_password_never_arms`, `arming_after_failures_needs_the_password_too`, `arming_checks_the_password_itself` (container, real `unix_chkpwd`), which fails when the check is removed |
| `unix_chkpwd` answering about someone else | It answers only about the user its caller really is; the helper keeps its caller's uid, so the two agree | `chkpwd.rs` | `arming_checks_the_password_itself` (container) |
| The hash compared in a way that leaks timing | libxcrypt hashes; the result is compared in constant time where libxcrypt wrote it | `sys/src/crypt.rs` | `hashes_and_verifies` |

## The caller's side: the PAM module

| Hazard | What the module does | Where | Tested by |
|---|---|---|---|
| The helper quits without reading, and the write raises SIGPIPE in the lock screen | The module keeps its own copy of the pipe's read end open until it has written, as pam_unix does | `pam/src/run.rs`, `ask_helper` | `a_broken_helper_fails_closed` ("quits without reading") |
| The host ignores SIGCHLD, or its handler reaps every child, so the exit status is lost | SIGCHLD set to its default while the helper runs, then put back, also during a panic | `pam/src/pam.rs`, `DefaultSigchld` | `a_host_that_ignores_sigchld_still_gets_answers`, `a_host_that_reaps_every_child_still_gets_answers`, `a_panic_puts_sigchld_back_and_the_password_still_works` |
| Two threads saving and restoring SIGCHLD at once lose the host's setting | properpin's own attempts take turns while SIGCHLD is changed; another module doing the same on another thread could still race, as with pam_unix | `pam/src/pam.rs`, `DefaultSigchld` | `attempts_on_several_threads_keep_the_hosts_handler` |
| A host thread looping on `waitpid(-1)` takes the helper's exit status | Nothing can stop it; the module then has no answer and refuses, and the password still works | `pam/src/run.rs`, `wait` | `a_host_thread_that_reaps_every_child_fails_closed` |
| The host's own child exits while SIGCHLD is at its default | The module waits for its own child only, so the host can still collect its child's exit status; its handler may miss that one signal, as with pam_unix | `pam/src/run.rs`, `wait` | `the_hosts_own_children_survive_an_attempt` |
| The lock screen's environment or files reaching the helper | An empty environment, `/` as working directory, the pipe as stdin, `/dev/null` for output; std's pipes are close-on-exec | `pam/src/run.rs`, `ask_helper` | Indirectly |
| A hung helper hangs the lock screen | Killed after 10 seconds, and the PIN refused | `pam/src/run.rs`, `wait` | Not tested (would take 10 seconds); see `docs/concerns.md` |
| The helper missing, killed, or answering oddly | Every answer but 0 refuses, and the password still works | `pam/src/run.rs`, `run` | `a_broken_helper_fails_closed`, `a_missing_helper_fails_closed` (container) |

## Installed permissions

`install.sh check` verifies each of these, and the container runs it after installing.

| Path | Owner and mode | Why |
|---|---|---|
| `/usr/local/libexec/properpin/properpin-helper` | `root:properpin 2755` | Setgid for reading hash files and keeping counts; only root can change it |
| `/etc/properpin/users/` | `root:properpin 0750` | The user can't list who has a PIN |
| `/etc/properpin/users/<user>` | `root:properpin 0640` | Root writes it (`sudo properpin set`), the helper reads it, nobody else |
| `/run/properpin/` | `root:properpin 1770` | The counts, out of every user's reach; sticky, so each file is replaced or deleted only by its owner |
| `/run/properpin/<uid>.state`, `<uid>.lock` | `<uid>:properpin 0600` | Created by the helper run by that user |
| `/var/lib/properpin/` | `root:properpin 1770` | The budgets, on disk, under the same rules as `/run/properpin` |
| `/var/lib/properpin/<uid>.budget` | `<uid>:properpin 0600` | Written by the helper run by that user, or by `properpin enable` as root, which gives it the same owner |
| The `properpin` group | no members, nobody's primary group, password locked in `/etc/gshadow` | Running the helper is the only way to get it; `check` reads gshadow, so it needs root |
