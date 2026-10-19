# Test ideas

What the tests still miss, as of 2026-10-19, most important first. The install script is left out on purpose: it is going to change a lot, so testing it now would be wasted effort.

## What exists

The suite is already broad, so what is missing is a few specific paths rather than more tests of the same kind:

- about 140 unit tests, with property tests for the attempt rules and the budget;
- `crates/pam/tests/stack.rs`: the real libpam with the freshly built module and checker binary (18 tests);
- `crates/checker/tests/checker.rs` and `crates/cli/tests/cli.rs`: the checker and CLI binaries against a sandbox;
- the container system test: 43 scenarios with the real `pam_unix`, setgid and several users.

## A bug the missing tests would catch

If the wall clock moves backwards between wrong guesses and the next correct PIN, that PIN forgives the guesses, so they never become suspicious and never reach the total. Confirmed with a throwaway program: two guesses an hour apart, the clock set back a day, then a correct PIN, and the budget ends with `pending []` and `total 0`.

The cause is `Budget::forgive` in `crates/core/src/budget.rs`: it keeps only failures with `at + window < now`, so every failure dated "in the future" is forgiven. This breaks the promise in that file's header that changing the clock can never take failures "out of the total".

An attacker at the keyboard can't move the clock, but ordinary events can: a dual-boot machine whose hardware clock is kept in local time, or an NTP correction. The likely fix is to forgive only failures between `now - window` and `now`, with a unit test for exactly this case.

## Integration tests

### The default target user under sudo

`sudo screenlock-pin set` without `--user` takes the user from `SUDO_USER`, or from `PKEXEC_UID` under pkexec. That is how people will really run it, and nothing tests it: the CLI tests remove both variables, and every container scenario passes `--user alice`.

Add a CLI test that sets `SUDO_USER` and one that sets `PKEXEC_UID`, and check whose PIN gets set. Add one container scenario that runs `sudo screenlock-pin set` as alice with no `--user`, reusing the temporary sudoers file the scenario "typed on a terminal without root, the command runs itself through sudo" already writes.

### A failed or cancelled PAM conversation

When `pam_get_authtok` fails, the module must answer `PAM_IGNORE`, count nothing, and leave the password working as before. This is what happens when Plasma 6.8 cancels an authenticator it switches away from. The harness in `crates/pamharness/src/lib.rs` can't make a conversation fail yet, so it first needs a small option for that; the test then belongs in `crates/pam/tests/stack.rs`.

### `enable` racing an attempt

The branch "the PIN's budget changed while asking" in `enable` (`crates/cli/src/main.rs`) never runs in any test. It is lower priority, and easier to test once that logic moves somewhere it can be called directly instead of only through the binary.

## Unit and property tests

### One combined model test

The property test in `crates/core/src/attempt.rs` turns the disable limits off, and the one in `crates/core/src/budget.rs` ignores pausing. A single model that covers pausing, disabling and forgiveness together, with clock steps that can go backwards, would have caught the bug described above, and would catch future bugs in how the rules interact.

### Parser properties

For any budget, `Budget::parse(&budget.format()) == Some(budget)`. And on random input none of these may panic: `kv::parse`, `Budget::parse`, `Settings::apply`, the PAM module's `Args::parse` and the checker's `Options::parse`. They are cheap to write, and the security depends on these inputs.

### Range edges for every setting

For each rule, the smallest and largest allowed values are accepted, and one past either end is refused. Keep it as one table, plus a check that the table covers every name in `RULES`, so a new setting can't be added without its edges tested. Today only a few edges are checked.

### The weekly mutation report

The `mutants.yml` workflow lists exactly which lines no test notices, which makes it the best guide for further unit tests. Read its latest "missed" list before writing more. It only covers `core` and `sys` today; adding the PAM module and the CLI to it is worth considering.

## Not worth adding

- more scenarios of the same kind as the existing ones;
- tests for the install script, until it settles;
- automating the real KDE greeter.
