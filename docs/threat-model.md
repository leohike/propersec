# screenlock-pin's threat model

Who might try to get into a session that screenlock-pin's PIN can unlock, what each of them can do, what stops them, and what is left. Written on 2026-10-22 for a reviewer reading it next to the code, and checked against the code at commit `72bf56f`. Every defence names the function it lives in and, where one exists, the test that shows it; every number was measured or computed for this page, and the PIN shapes behind the numbers section below says how.

This is the one place for the threat model. `docs/chaos/security-target.md` came before it and keeps its reasoning, and the rest of `docs/chaos/` holds the research and the history behind the decisions. Some of those notes describe earlier designs (the pepper, the expiry, an `unpause` that checked the password); where they disagree with this page, this page follows the code.

The scope is attackers who want into the locked session. Lock-outs and denial of service, the build and install path, the supply chain and copies of secrets in memory are threats too, but they are left out here, as the section on what this page doesn't cover explains.

## What is protected

- **The locked session.** Everything the user has open: files, mail, a password manager left unlocked. This is the asset; the rest only matters as a way to it.
- **The PIN itself.** It unlocks nothing but this user's lock screen, so it is worth little on its own, unless it is also the PIN of a phone or a bank card.
- **The password.** screenlock-pin must never make it easier to get. The password still guards login, `sudo`, polkit, a text console, SSH and the disk.
- **The PIN hashes and the failure counts.** Means, not ends: a hash is a way to the PIN, and resetting the counts is a way to more guesses.

## How it fits together

The lock screen (kscreenlocker's greeter, or in 6.8 its PAM worker) runs as the locked user and authenticates through libpam with the service `kde`. After `integrate-into-pam.sh add`, `/etc/pam.d/kde` pulls in `/etc/pam.d/screenlock-auth` where it used to pull in the stock `password-auth`, and that file holds three lines: the module's `check` line (`sufficient`), the stock `password-auth` substack, and the module's `after-password-auth` line (`optional`).

On the `check` line, `pam_sm_authenticate` (`crates/pam/src/pam.rs`) reads what was typed and `run` (`crates/pam/src/run.rs`) pipes it to the setgid PIN checker, `/usr/local/libexec/screenlock-pin/screenlock-pin-checker check`, the way pam_unix feeds `unix_chkpwd`. The PIN checker decides and answers with its exit code. Exit 0 is the only answer that unlocks; anything else makes the module return `PAM_IGNORE`, and the stock stack checks the same input as the password, exactly as it would without screenlock-pin.

After the stock stack has accepted the password, the lock screen calls `pam_setcred`, which libpam replays only down the lines `pam_authenticate` went through. The `after-password-auth` line's `pam_sm_setcred` then asks the PIN checker for `unpause`, which forgives the user's recent failures and starts the consecutive count over. After a PIN unlock or a failure, that line never runs (`setcred_reaches_the_after_password_auth_line_after_a_password_unlock_only` in `crates/pam/tests/stack.rs`, `setcred_follows_a_password_unlock_only` in the container test).

The rules themselves are in `crates/core`, with no I/O and no `unsafe`: `try_unlock_with_pin` and `unpause_pin_after_password_unlock` in `attempt.rs`, and the failure budget in `budget.rs`.

## Trust boundaries

| Process | Runs as | What it can reach | Trusted |
|---|---|---|---|
| The greeter, libpam and `pam_screenlock_pin.so` | The locked user | What was typed; nothing of screenlock-pin's on disk | As much as anything else the user runs: the PIN checker doesn't trust it |
| `screenlock-pin-checker`, installed `root:screenlock-pin 2755` | Its caller's uid, with the `screenlock-pin` group added | Every hash, to read; its caller's own budget and lock file | It holds the secrets, and treats every caller as hostile |
| `screenlock-pin set`, `enable`, `remove`, `doctor` | root, through `sudo` | Everything | Yes |
| root, the kernel, libpam, libxcrypt, glibc | | | Yes |

| File | Owner and mode | Holds |
|---|---|---|
| `/etc/screenlock-pin/users/<user>` | `root:screenlock-pin 0640`, in a directory `root:screenlock-pin 0750` | That user's yescrypt hash, and nothing else |
| `/etc/screenlock-pin/config` | `root:root 0644` | One policy for every user, and never a hash |
| `/var/lib/screenlock-pin/<uid>.budget` and `<uid>.lock` | `<uid>:screenlock-pin 0600`, in a directory `root:screenlock-pin 1770` | The counts: the user owns them, but can't enter the directory |

The `screenlock-pin` group has no members, is nobody's primary group, and has a locked password, so running the PIN checker is the only way to get it; `install.sh check` fails otherwise, and the container test's `the_group_stays_empty_and_locked` shows it. The binary is root's, so the group can't change it (`the_group_cannot_change_the_pin_checker`).

## Assumptions

- **Full-disk encryption**, with no unencrypted swap or hibernation image. Without it, anyone holding the powered-off disk reads the hashes, and everything else besides.
- **Root and the kernel are not the attacker.** Root can unlock any session, read any file and install a PAM module of its own, so screenlock-pin doesn't defend against it, as the section on attackers it doesn't try to stop says.
- **The lock screen behaves as kscreenlocker 6.7.5 and 6.8 do**: it runs as the locked user, uses the service `kde`, asks once per attempt with the PIN and the password in the same field, and calls `pam_setcred` only after a successful `pam_authenticate`. `docs/chaos/kscreenlocker-pam-contract.md` has the details. Fingerprint and smartcard unlocks go through their own services (`kde-fingerprint`, `kde-smartcard`) and never meet the PIN; they are outside this model.
- **Fedora's stock authselect layout**, with `auth substack password-auth` in `/etc/pam.d/kde`, and faillock off, as it is by default.
- **The installed layout** is the one in the trust boundaries table, as `install.sh check` verifies it.
- **The wall clock can't be set by the attacker.** Setting it takes root; `docs/chaos/current-concerns.md` explains why the network and a reboot don't change that.

## The attackers at a glance

| Attacker | With the PIN | With the password only | Difference |
|---|---|---|---|
| A thief with the running, locked machine | 3 guesses, then only the password | Guessing a long password is hopeless | Weaker, by 3 guesses at a short secret |
| Someone with repeated access to the keyboard | About 63 guesses per PIN, at most about 10 a day, more if they can time them just before the user returns | Hopeless | Weaker, by a bounded number of guesses |
| Someone watching the PIN being typed | A short secret typed many times a day; unlocks at the first try | A long secret, now typed rarely | The PIN is easier to catch, the password harder |
| Someone holding a copy of the files | A hash that falls quickly for a short PIN, then needs the keyboard too | `/etc/shadow`, uncrackable for a strong password | Weaker, but they need a second attack to use it |
| Code running as the user | Can't read the hash or the counts, but can guess the PIN without limit through the PIN checker | Already inside the session | None for the session; the PIN can be recovered |
| Another local user | Nothing of anyone else's; at that user's keyboard, as the rows above | The same | None |
| A local user who exploits the PIN checker | Every user's hash, to crack offline | The same user gets nothing | Weaker, by every hash |
| Someone on the network | Nothing: no network service meets the PIN | The same | None, while no service running as the user names `kde` |
| Root, RAM readers, coercion | Win | Win | None |

## The PIN shapes behind the numbers

Every number below assumes a PIN chosen at random from its shape, which is the best case. PINs people make up are far from uniform: the commonest few cover a large share of all PINs, and an attacker tries those first, so the odds for a chosen PIN are worse than these, often much worse.

| PIN, chosen at random | Possible PINs | Allowed by the default rules |
|---|---|---|
| 4 digits | 10,000 | No: only with `required_non_digits_count = 0` |
| 4 lowercase letters | 457,000 | Yes: the shortest PIN the defaults allow |
| 6 lowercase letters | 309 million | Yes |
| 2 words from the EFF long list | 60 million | Yes |
| 3 words from the EFF long list | 470 billion | Yes |

The word counts assume the attacker knows how the words are joined; trying four spellings (a space, joined, a hyphen, capitalized) multiplies the offline and code-as-the-user times by about four.

The hash timings were measured on 2026-10-22 on an Intel Core i7-11850H with libxcrypt 4.5.2, hashing through `crypt_rn` as `crates/sys/src/crypt.rs` does, with four cores busy at once: about 14 ms of one core per guess at `hash_cost` 5 (the default), 113 ms at 8 and 970 ms at 11, with 16 MiB, 128 MiB and 1 GiB of memory per hash. One hash alone on an idle machine took 10.5, 90 and 865 ms. Cost 5 is the same `$y$j9T$` Fedora uses for `/etc/shadow`.

## A thief with the running, locked machine

Someone takes the laptop while it is on and locked, or sits down at a desk whose owner won't be back. They can type anything at the lock screen and wait as long as they like. They can't run code: the session is locked, a text console asks for the password through `login`, which never loads the module, and a reboot ends at the disk's passphrase or at the login screen, neither of which takes the PIN (`docs/etc/why-not-loginscreen.md`).

**What stops them.**

- **Every input is counted before it is checked.** `try_unlock_with_pin` records the failure and one more consecutive failure (`Budget::count_attempt`) and saves the budget before `Hasher::verify` runs, and takes both back on a match. A greeter or worker killed in the middle of a check has its guess counted all the same: `a_failure_is_saved_before_the_hash_is_checked` and `every_check_happens_with_its_attempt_already_counted` in `crates/core/src/attempt.rs` fail if the order changes, and the container's `a_killed_worker_loses_no_count` kills a 6.8-style worker at chosen and random moments.
- **Three consecutive failures pause the PIN** (`max_failures`, `Budget::paused`). A paused PIN is refused without being checked and records nothing, so typing on can't get a guess through or push it further (`paused_even_the_right_pin_is_refused_until_the_password`, `a_paused_or_disabled_pin_records_nothing`). The count is on disk, so a reboot or a crash doesn't reset it.
- **Only a password unlock unpauses it.** `unpause` comes from `pam_sm_setcred` on the `after-password-auth` line, which libpam reaches only after the stock stack accepted the password, never after a wrong input (`a_wrong_password_never_unpauses_the_pin`, in the stack tests and the container).
- **Attempts take turns.** Every read and write of the budget happens under the user's lock file (`UserFiles::lock` and `flock` in `crates/sys/src/files.rs`), so parallel attempts can't overtake each other's counts (`concurrent_wrong_pins_are_all_counted`).
- **Everything that goes wrong fails closed.** Only the PIN checker's exit 0 makes the module answer `PAM_SUCCESS` (`answer` in `crates/pam/src/run.rs`). A missing, killed or hung PIN checker (killed after 10 seconds, `HELPER_TIMEOUT`), a panic (caught in `pam_sm_authenticate`), a PAM line the module can't read, or a damaged budget all refuse the PIN and leave the password to the stock stack (`a_broken_pin_checker_fails_closed`, `a_missing_pin_checker_fails_closed`, `a_bad_pam_line_refuses_instead_of_guessing`, `a_damaged_budget_refuses_the_pin`).

**The numbers.** Three guesses in all, however long they keep the machine: 1 in 3,300 for 4 random digits, 1 in 150,000 for 4 random letters, 1 in 20 million for two random words.

**What is left.** A weak PIN, which three guesses can find if it is one of the commonest few. Everything a running machine exposes beyond the lock screen, such as its memory, which the section on attackers screenlock-pin doesn't try to stop covers.

## Someone with repeated access to the keyboard

A flatmate, a colleague or a partner who gets a few minutes alone with the locked machine every so often, while its owner keeps using it. Unlike the thief, they benefit from the owner coming back: a correct PIN starts the consecutive count over, so without more they could guess twice at every absence, forever.

**What stops them.** The failure budget (`crates/core/src/budget.rs`), across reboots, with nothing to notify:

- **Every input that doesn't unlock is a failure,** wrong passwords included, since the `check` line sees everything before the stock stack does. An empty input isn't one.
- **The user's own typos are forgiven:** a correct PIN forgives the failures of the 45 seconds before it (`forgive_before_correct_pin`, in `Budget::pin_matched`), a password unlock those of the 90 seconds before it (`forgive_before_correct_password`, in `Budget::password_unlocked`).
- **A failure nothing forgave in time is suspicious,** judged at the PIN checker's next run (`Budget::judge`).
- **Too many disable the PIN:** 10 suspicious failures within 24 hours, 25 within 7 days or 60 since the PIN was set. A disabled PIN is refused like a paused one, and the password doesn't bring it back; only root does, with `screenlock-pin enable`, which keeps the count since the PIN was set, or `set`, which starts a new PIN's budget.
- **A flood can't push failures out.** At most 50 failures wait to be judged and the oldest beyond that is judged suspicious at once; the count since the PIN was set never goes down (`a_flood_of_failures_is_judged_rather_than_dropped`, and the property test `nothing_is_ever_lost`).

The property test `a_slow_attacker_is_stopped` drives the attack itself, a guess and then the user's correct PIN some time later, at every pace from 46 seconds to three days, and shows the attacker never gets more than the total limit plus 3. The container shows it on a real install (`the_slow_attack_is_stopped`, `unforgiven_guesses_disable_the_pin`, `the_lifetime_limit_takes_a_new_pin`).

**The numbers.** About 63 guesses per PIN, whatever the pace, and no more than about 10 in a day: 1 in 160 for 4 random digits, 1 in 7,000 for 4 random letters, 1 in a million for two random words. A disabled PIN is also a signal: the owner finds their PIN refused even after the password, and `screenlock-pin status` shows the suspicious failures.

**What is left.**

- **Guesses timed just before the owner returns are forgiven as the owner's typos.** The budget tells the attacker from the owner by time: the owner follows a typo with a correct unlock within seconds, the attacker walks away. An attacker who can see the owner coming back, and guesses in the last 45 seconds before the owner types the PIN, has those guesses forgiven, and the consecutive count starts over. Two such guesses a time go unnoticed. A third pauses the PIN, so the owner's PIN is refused, which they may notice, and their password then forgives all three. With 2 guesses on each of 4 returns a working day, about 2,000 guesses a year: 1 in 5 for 4 random digits, 1 in 230 for 4 random letters, 1 in 30,000 for two random words. The windows can be shortened in the config, down to 0, at the price of the owner's own typos becoming suspicious; nothing else in the code addresses it.
- **Nothing tells the owner as it happens.** Suspicious failures are in the journal and in `screenlock-pin status`, which nobody reads unprompted; an alert is planned (`docs/chaos/alert-popup-idea.md`).
- **`enable` run again and again** gives up to the total limit of guesses on one PIN, at root's choice.

## Someone watching the PIN being typed

Someone behind the user, a camera, a reflection, or a keylogger in the keyboard cable. No software defends against this, and the budget doesn't come into it: a watched PIN unlocks at the first try, whenever the PIN is enabled and the attacker is at the locked keyboard.

**What limits the damage.**

- **The PIN unlocks the lock screen and nothing else.** The other services' PAM files don't name the module, and the container test tries the PIN on `sudo`, `su`, `login`, `system-auth`, `password-auth`, `passwd` and `other` and finds it refused and the module never loaded (`the_pin_works_at_the_lock_screen_only`). Programs that authenticate as root are refused anyway: the module steps aside when its real or effective uid is 0 (`calling_account` in `crates/pam/src/run.rs`), and the PIN checker refuses uid 0 (`run` in `crates/checker/src/main.rs`). So a watched PIN gives no `sudo`, no login, no SSH and no disk.
- **The PIN may not be the password.** `screenlock-pin set` runs as root and compares the new PIN with the user's hash in `/etc/shadow`, whatever its scheme (`Yescrypt::is_password` in `crates/sys/src/crypt.rs`, `set` in `crates/cli/src/main.rs`), and refuses a match (`the_pin_may_not_be_the_password`, `set_refuses_the_password_and_the_pin_works_at_once`).
- **The password is typed less often,** now that the PIN does the daily unlocks, so it is harder to watch.

**What is left.** Everything the PIN unlocks, until the user changes it; nothing expires it (`docs/chaos/security-target.md`, why there is no expiry). The comparison with the password catches an exact match only, at `set` only, and is skipped with a warning for users without an entry in `/etc/shadow` such as LDAP or systemd-homed users (`without_a_shadow_entry_the_pin_is_not_compared`); a password changed later to the PIN goes unnoticed. A longer PIN typed with care makes watching harder; nothing makes it impossible.

## Someone holding a copy of the files

A backup of `/etc` or `/var/lib`, a snapshot, a disk image taken with the disk unlocked, a disk sent for repair without its encryption, or a bug in some program that reads files as root. With full-disk encryption, as assumed, the disk alone gives nothing.

**What they get.** `/etc/screenlock-pin/users/<user>`: the PIN's yescrypt hash at `hash_cost`, and nothing else (`Settings::apply` refuses anything else in a user's file). There is no pepper since 2026-10-16, so the hash can be attacked directly; `docs/chaos/security-target.md` explains why the pepper went. To use the PIN they then need the second attack of the rows above: to be at the keyboard, with the screen locked and the PIN enabled.

**The numbers.** The average time to crack, in time of one core (divide by the cores used), at an assumed $0.02 per core-hour of rented machines:

| PIN, chosen at random | Cost 5, the default | Cost 8 | Cost 11, the highest |
|---|---|---|---|
| 4 digits | about a minute | 9 minutes | 80 minutes |
| 4 lowercase letters | under an hour | 7 hours | 3 days, about $1 |
| 6 lowercase letters | 25 days, about $12 | 200 days, about $100 | 5 years, about $830 |
| 2 EFF words | 5 days, about $2 | 40 days, about $19 | 340 days, about $160 |
| 3 EFF words | 100 years, about $18,000 | 840 years, about $150,000 | 7,200 years, about $1.3 million |

These assume CPUs. yescrypt's memory use is meant to keep graphics cards and custom hardware from doing much better; that is its design's claim, not measured here.

**What limits the damage.** The hash is useless away from the machine, except for a PIN reused elsewhere. The same copy usually holds `/etc/shadow`, which for a strong password is worth nothing, and the user's files, which are worth more than a PIN that opens only the lock screen. A higher `hash_cost` (up to 11, applied at the next `set`) slows cracking by the factors above, and makes every input at the lock screen, the password included, take that long to check.

**What is left.** A short PIN falls in minutes. `install.sh uninstall` keeps the hashes (`docs/chaos/uninstall-should-purge-pin-hashes.md`), so they outlive screenlock-pin in later backups. Excluding `/etc/screenlock-pin` and `/var/lib/screenlock-pin` from backups, or encrypting backups, closes this row for backups.

## Code running as the user

Malware, a compromised browser or chat app, or a program planted during a moment at an unlocked desk: anything running with the user's uid. It is already inside the session the lock screen guards: it can read the user's files and, as `docs/chaos/security-target.md` notes, unlock the session directly. What it can do to the PIN is what matters here.

**What stops it.**

- **It can't read the hash or the counts.** The user's file is `root:screenlock-pin 0640` in a `0750` directory, and the budgets are in a `1770` directory only the group can enter (`the_user_cannot_reach_the_files`). This is what closes the leak `docs/chaos/threat-insider-hash-leak.md` describes, a hash copied in seconds at an unlocked desk.
- **It can't choose whom or what the PIN checker answers about.** The caller is the real uid from the kernel (`current_uid` in `run`, `crates/checker/src/main.rs`); no argument names a user, and `UserFiles::new` refuses a name that could leave `users/` (`a_bad_user_name_is_refused_before_any_file`). The `--dev-*` options that move the files are refused unless `AT_SECURE` is clear and the real and effective ids agree (`dev_options_allowed` in `crates/checker/src/lib.rs`, `secure::elevated`): `dev_options_need_both_guards_to_agree` tests the truth table and the container's `dev_options_are_refused_under_setgid` the installed binary.
- **It can't poison the PIN checker's start.** `start_clean` (`crates/checker/src/secure.rs`) reopens closed standard descriptors, closes every other one, resets every signal, clears the environment, sets the umask and the working directory, and a panic aborts without printing; the kernel makes the setgid process undumpable and untraceable by its caller, and the loader ignores `LD_PRELOAD` (`a_poisoned_start_changes_nothing`, locally and in the container). Input is read into one fixed buffer of 512 bytes (`read_input`), and anything unexpected on the command line is refused (`anything_unexpected_on_the_command_line_is_refused`).

**What it can do.** Guess the PIN without limit. It can run `screenlock-pin-checker check` with a guess and then `screenlock-pin-checker unpause`, which takes no password (`unpause_pin` in `crates/checker/src/lib.rs`, accepted in `docs/etc/current-setcred.md`): that forgives the failures of the last 90 seconds and starts the consecutive count over, so no guess ever becomes suspicious and the PIN never pauses. Tried on 2026-10-22 through the real binary in its local-test mode: 300 wrong guesses, each followed by `unpause`, left a budget with nothing pending, nothing suspicious and a consecutive count of 0. The lock makes one user's attempts take turns, so the pace is one hash at a time: 65 guesses a second on the machine above with the budget on an encrypted btrfs disk, 78 with it in memory. On average that finds 4 random digits in about a minute, 4 random letters in about an hour, two random words in about 5 days, 6 random letters in about four weeks; three random words would take about a century. Each guess leaves two lines in the journal ("not the PIN, consecutive failure 1 of 3" and "unlocked with the password, PIN enabled"), so it is loud for anyone who looks.

**Why that is accepted.** The session is already lost to such code, with or without screenlock-pin. What the PIN adds is a way to learn the PIN without waiting for the user to type it, which is worth something only where the PIN is reused, or to let someone else in at the keyboard later, which the code could do itself. `docs/chaos/security-target.md` calls this guessing "a little faster than keylogging"; the numbers above say a short PIN falls within the hour.

**What is left.** A reused PIN. Undoing it would mean `unpause` checking the password again, which it did until 2026-10-18 and which broke the PIN unpause for sssd and systemd-homed users, or limiting how often `unpause` may forgive, which nothing yet does. The code could probably also drive the `kde` PAM service itself (reasoned in `docs/etc/current-setcred.md`, not tried); that gives it nothing the PIN checker doesn't.

## Another local user

Someone with an account of their own on the same machine, who wants into alice's session.

**What stops them.** The PIN checker answers only about its caller, so bob running it gets his own PIN, his own counts and his own `status`, never alice's (`another_user_gets_nothing` in the container, `each_caller_gets_only_their_own_pin_and_counts` in `crates/checker/src/lib.rs`). He can't read her hash or her counts, nor list who has a PIN (`users/` is `0750`). The module refuses to check a PIN for any user but the one its process runs as (`calling_account`, `the_pin_only_works_for_the_user_the_lock_screen_runs_as`).

**What is left.** At alice's keyboard, bob is the thief or the repeated-access attacker above, with their limits.

## A local user who exploits the PIN checker

The PIN checker runs with more rights than its caller, so a bug in it matters more than a bug anywhere else in screenlock-pin. Suppose bob finds one and runs code of his own with the `screenlock-pin` group added, still as his own uid.

**What he gets.** Every user's PIN hash, since the group reads them all, to crack offline as in the copy-of-the-files row. If alice's PIN is also her password, which `set` refuses only for an exact match, he gets her password with it, and with that her login and `sudo`: the one way screenlock-pin can be strictly worse than no screenlock-pin (`docs/chaos/why-pin-same-as-password-bad.md`).

**What he doesn't get.**

- **The PIN checker itself:** it is root's, so the group can't change, replace or rename it, and it can't capture what anyone else types (`the_group_cannot_change_the_pin_checker`).
- **The hashes and the config, to write:** both are root's, and `users/` isn't writable by the group.
- **Anyone else's counts:** alice's budget and lock file are hers, `0600`, in a sticky directory, so bob's process can neither read nor replace nor delete them (`one_users_pin_checker_cannot_touch_anothers_counts`, which fails without the sticky bit).
- **Files planted in her name:** `screenlock-pin set` creates the budget and the lock file as root for the user, and the PIN checker only ever opens them (`UserFiles::start_budget`, `open_lock`, `load_budget`), so while hers exist nobody else's can stand in their place, and one that isn't hers is refused (`a_missing_or_planted_lock_file_is_refused`, `planted_counts_are_refused`, `a_damaged_or_planted_budget`).
- **Anyone else's password:** the passwords alice types reach only her own PIN checker runs, which bob can't trace.

**How small the target is.** The decisions are in `crates/checker/src/lib.rs` and `crates/core`, both `#![forbid(unsafe_code)]`, and the workspace denies `unsafe` everywhere else except `crates/checker/src/secure.rs` (the clean start and syslog), `crates/sys/src/crypt.rs` (libxcrypt) and `crates/sys/src/clock.rs` (local time). Its inputs are one request word, at most 512 bytes on stdin, and files it checks on the open file descriptor before reading at most 4 KiB of each (`read_trusted`, `read_regular_file`). `docs/chaos/pin-checker-review.md` is a hazard-by-hazard checklist for reviewing it, though parts of it describe the `unpause` that checked the password.

**What is left.** The hashes, readable by anyone who breaks the PIN checker. The PIN checker resolves its caller through NSS (`Account::by_uid`), which loads whatever modules `/etc/nsswitch.conf` names, with the group's rights, as `unix_chkpwd` and `su` do. No one but its author has reviewed it.

## Someone on the network

No network service meets the PIN today. It isn't in `password-auth` or `system-auth`, which `sshd`, Samba and the rest use (`docs/etc/where-the-pin-belongs-in-pam-IMPORTANT.md` explains why it must not be), and services that authenticate as root are refused by both the module and the PIN checker, as the section on someone watching the PIN says.

**What is left.** The module doesn't look at which PAM service called it. A program running as the user that authenticates through `kde` or `screenlock-auth`, such as a remote desktop server started in the session and pointed at either, would accept the PIN from the network. The budget would still bound the guesses, since a remote attacker can't run `unpause`, and the guesses would disable the PIN; refusing every service but `kde` is planned (`docs/chaos/plan.md`).

## Attackers screenlock-pin doesn't try to stop

- **Root on the running machine,** or anyone who can act as root: it can read the hashes, log the password, unlock the session with `loginctl unlock-session` and install a PAM module of its own. The same goes for an administrator who sets a PIN for someone else, lowers `hash_cost` or re-runs `enable`; `docs/chaos/current-concerns.md` dismisses these together.
- **Anyone who can read the running machine's memory,** by a cold boot, DMA or a debugger: they get the disk's key, which is worth more than any PIN.
- **Coercion.** A PIN, like a password, is given up under force.
- **Someone who tampers with the hardware or the boot chain** before the user next types anything, which full-disk encryption alone doesn't stop either.

A strong password alone doesn't stop any of these either.

## Known gaps

The open points of the sections above, most serious first.

- **Code running as the user can guess the PIN without limit,** about 65 guesses a second, by following each guess with `unpause`. Accepted, since such code owns the session already, but it recovers a short PIN within the hour, which matters wherever the PIN is reused. Possible answers are a limit on how often `unpause` may forgive, or the password check it had until 2026-10-18; neither is planned.
- **The forgiveness windows can be gamed** by an attacker at the keyboard who can time guesses within 45 seconds of the owner's return: 2 unnoticed guesses a time, outside every limit of the budget. Shorter windows trade against the owner's own typos; an alert would make it visible.
- **No outside review.** All the code was written through agentic coding, and nobody but its author has reviewed it (README.md, Status); for the PIN checker that matters most.
- **A copy of the files cracks a short PIN quickly.** The default `hash_cost` is 5, there is no pepper, and the hashes survive `uninstall`; purging them is planned.
- **With faillock on, a right PIN still unlocks while faillock has the account locked,** because the `check` line runs before the substack that holds faillock (`docs/chaos/current-concerns.md`). Faillock is off on stock Fedora; asking faillock first from the PIN checker is deferred.
- **The module accepts any PAM service** that runs as the user, as the section on someone on the network says. Planned.
- **The PIN-equals-password check is narrow:** an exact match, at `set`, for users with an entry in `/etc/shadow`. Decided on 2026-10-17 to leave it there.
- **Anything `password-auth` accepts unpauses the PIN,** a FIDO key with authselect's `with-pam-u2f` too (reasoned, not tested). Probably right, since the key is stronger than the password, but not yet a stated decision (`docs/chaos/plan.md`).
- **Nothing alerts the user** to suspicious failures or a disabled PIN as it happens. Planned.

## What this page doesn't cover

Threats that don't lead into the locked session, each with notes of its own:

- **Lock-outs and denial of service:** a module libpam can't load, a deleted `/etc/pam.d/screenlock-auth` while `kde` names it, a hung PIN checker, or anyone at the keyboard disabling the PIN with 10 wrong inputs. The README's sections on the PAM files and the uninstall cases, `docs/chaos/install-uninstall-with-a-broken-screenlock-pin.md` and `docs/chaos/concerns.md`.
- **The build and install path:** a toolchain that links the setgid PIN checker or the module against libraries a user can write, and `install.sh` running as root. The README's section on installing.
- **The supply chain:** dependencies running inside the lock screen, unsigned releases, who can push to `main`. `docs/chaos/before-anybody-uses-this.md`.
- **Copies of secrets in memory:** libpam's, the greeter's and the PIN checker's copies of what was typed, core dumps, swap and hibernation. The README's section on secrets in memory and `docs/chaos/pin-pam-copy.md`.
- **Unlocks that never meet the PIN:** fingerprint, smartcard and face unlock through their own PAM services.

## Where to read more

- `docs/chaos/security-target.md`: the earlier, shorter assessment, and why the pepper and the expiry went.
- `docs/chaos/physical-vs-remote-attacks.md`: why a PIN belongs at the lock screen and not at `sudo`.
- `docs/chaos/threat-insider-hash-leak.md`: the scenario that led to the setgid PIN checker.
- `docs/chaos/pin-checker-review.md`: the PIN checker's hazards, one by one.
- `docs/etc/current-setcred.md`: why `unpause` takes no password.
- `docs/etc/where-the-pin-belongs-in-pam-IMPORTANT.md`: why the PIN sits in `kde` and nowhere else.
- `docs/chaos/concerns.md` and `docs/chaos/current-concerns.md`: the long tail of open points.
