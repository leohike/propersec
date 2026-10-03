# A test harness closer to the real lock screen

A report from 2026-10-03 on the plan row "Harness closer to kscreenlocker": what the real lock screen does that properpin's tests don't, why that matters more since the PIN check moved into a helper, what the work would be, and what it is likely to find. The report was written from source first; the work was then done the same day, and What was done, and what it found, right below the short version, records the outcome. `docs/kscreenlocker-pam-contract.md` has the wider comparison of how kscreenlocker calls PAM; this report is about the lifecycle and the host process.

Sources, in the clone at `/home/shared/projects/kscreenlocker`:

- `v6.7.5`, what the development machine runs today: `greeter/greeterapp.cpp`, `greeter/pamauthenticator.cpp`, `greeter/pamauthenticators.cpp`;
- `master` (9843c147), which carries the 6.8 code: `greeter/worker/main.cpp`, `greeter/worker/prctls.h`, `greeter/pamauthenticator.cpp`;
- properpin's own `crates/pam/src/run.rs` (`ask_helper`, `wait`), `crates/pam/src/pam.rs` (`DefaultSigchld`), `crates/pamharness/src/lib.rs` and `crates/pam/tests/stack.rs`.

## The short version

properpin's tests call PAM the way a simple test client does: a fresh PAM session for each attempt, on one thread, in a process that does nothing else. The real lock screen keeps one session for many attempts, runs several authenticators side by side, and in 6.8 kills attempts midway. That didn't matter much while the module was a library that did its work and returned. Since the setuid (now setgid) helper, the module starts a child process from inside the lock screen and needs that child's exit code, because the exit code is the answer. That makes process-wide state part of properpin's correctness: the SIGCHLD setting, which children get reaped by whom, and what other threads are doing at the same moment. None of that is tested today.

The work is mostly test code: a PAM session that runs many attempts, hosts that misbehave in the ways real hosts do, a long-lived worker that gets killed, and checks that every process exits cleanly. Small to medium effort. The likeliest finding, if any, is a host that reaps every child or two threads racing over SIGCHLD; the likeliest fix is reading the helper's answer from a pipe instead of its exit code, which removes the dependence on SIGCHLD altogether.

## What was done, and what it found

Everything in What the work would be below was built, except the panic point, which went into the existing `test_panic` argument rather than a new one: it now panics just after the guard is set, instead of before anything happens.

- **The harness:** `PamSession` in `pamharness` keeps one handle for many attempts, calls `pam_setcred(PAM_REFRESH_CRED)` after a success and ignores the result, and sets a `PAM_FAIL_DELAY` callback that records the delay. `PamClient::authenticate` is now a session of one attempt, so every older test got the callback and `pam_setcred` too. `pamharness::host` sets SIGCHLD the ways real hosts do.
- **`stack.rs`:** a session test (every attempt asks again, the counts carry on, `pam_setcred` only after a success), and six host tests, each in a process of its own: SIGCHLD ignored, a handler reaping every child, a thread looping on `waitpid(-1)`, the host's own child exiting during an attempt, four threads at once, and a panic inside the guard.
- **The container:** a `worker` mode that keeps one session for a line-by-line stream of attempts; a scenario running the password, the PIN, a wrong PIN and the PIN again on it; a scenario killing it 16 times while it checks a wrong PIN; every attempt process checked for a clean exit; no helper left running after any scenario; and `podman run --init`, so orphaned helpers are reaped as on a real system.

What it found:

- **The race between threads is real.** Four threads, each on its own session, lost the host's SIGCHLD handler in the first run, exactly as in the table under Two threads at once. It is latent for the real lock screen: properpin runs on one thread there, and on Fedora the fingerprint and smartcard stacks (`pam_env`, `pam_fprintd`, `pam_deny`, `pam_debug`) start no children. The fix is small: a process-wide mutex in `DefaultSigchld`, held from saving to restoring, so properpin's own attempts take turns. Another module doing the same dance on another thread could still race with it, as with pam_unix, which the pipe fix below would end.
- **A thread looping on `waitpid(-1)` wins every time.** All five correct PINs were refused in each run, the wrong PINs never unlocked, and the password still worked: fail closed, as predicted. Left as documented behaviour.
- **Everything else passed at once:** SIGCHLD ignored, a reaping handler (which never saw the helper), the host's own child, the panic, one session for many attempts, and the 16 kills, where the guess reached the helper in 13 or 14 rounds and not in the others, and logs, state and budget always agreed.
- **A correct PIN takes about 20 to 25 ms** through the real stack in the container, under the 50 ms that 6.8 calls too quick. The minimum-duration row in `docs/plan.md` now has a measurement behind it.
- **The clean-exit check doesn't catch the unload crash in a worker.** With `-z nodelete` removed, every container scenario still passed: glibc keeps a library mapped while it has thread-local destructors pending, so the crash needs a thread that exits after `pam_end`, which the load/unload test in `stack.rs` covers. The check stays, for any other crash at exit.

Checked by breaking things on purpose: with the guard's restore skipped during a panic, the panic test fails; without the mutex, the four-thread test fails. The pipe fix was not made: the one problem the tests found has a smaller fix, and the remaining hazards are a host thread stealing exit statuses and another module racing on another thread, neither of which the real lock screen does today.

## What the real lock screen does

### Plasma 6.7.5, today

- **PAM runs on a background thread** inside `kscreenlocker_greet`: each `PamAuthenticator` moves its worker object onto its own `QThread` (`pamauthenticator.cpp`, the `moveToThread` call).
- **One PAM session per authenticator for the greeter's whole life.** `pam_start` runs once (`pamauthenticator.cpp`, around line 238), then `pam_authenticate` again and again on the same handle (line 192), and `pam_end` only when the greeter goes away (line 176).
- **Three authenticators, started together.** `greeterapp.cpp` lines 138 to 143 create one for the password (`kde`), one for fingerprints (`kde-fingerprint`) and one for smartcards (`kde-smartcard`). `PamAuthenticators::startAuthenticating()` calls `tryUnlock()` on all of them in a row, so several `pam_authenticate` calls run at the same moment, on different threads of one process. properpin's lines are only in `kde`, but whatever the other two stacks do happens in the same process at the same time.

### Plasma 6.8 (`greeter/worker/main.cpp`)

- **One `kscreenlocker_worker` process per authenticator,** started by the greeter as the same user and talking to it over a private D-Bus connection. It keeps one PAM session and serves many `Authenticate` calls on it until it is cancelled.
- **Cancelling kills it.** The greeter sends SIGTERM and then SIGKILL 25 ms later (`pamauthenticator.cpp`, `cancel`), so an attempt can end anywhere, including inside properpin's module.
- **The worker dies with its parent:** `PRCTLs::dieWithParent()` sets `PR_SET_PDEATHSIG` to SIGKILL at the top of `main`, and it refuses to run if already orphaned.
- **It is non-dumpable** unless debug logging is on (`PRCTLs::setDumpable`).
- **Every `pam_authenticate` is timed.** At 50 ms or less the service is marked unavailable, whatever the result (line 318). That is the minimum-duration row in the plan; the harness is where its measurement would live.
- **`pam_setcred(PAM_REFRESH_CRED)` after a success,** errors ignored (around line 327).
- **The failure delay sleeps inside `pam_authenticate`,** in the worker's `PAM_FAIL_DELAY` callback (`startFailedDelay`, `QThread::sleep`).
- **`pam_end` runs as the worker exits** (the `default_delete<pam_handle_t>` at the top of the file), and then `exit()` runs the main thread's thread-local destructors: the pattern of the unload crash, rust-lang/rust#91979.

### What properpin's tests do instead

- `pamharness` starts and ends a PAM session for every attempt (`PamClient::authenticate`).
- `stack.rs` runs attempts one at a time. `survives_many_loads_and_unloads_across_threads` uses threads, but only to load and unload the module many times, each thread with its own session, one attempt each.
- The container test runs each attempt in its own short process, as the user, which is closer to 6.8 but still one attempt per process, and it doesn't check how that process ended.
- Nobody calls `pam_setcred`, nobody sets a fail-delay callback (libpam sleeps), and the host process never touches SIGCHLD.

## Why it matters now

### The helper's answer depends on SIGCHLD

When a child process exits, the kernel keeps its exit code until the parent collects it, which is called reaping it (`waitpid`). The SIGCHLD setting of the parent decides how that goes, and it is one setting for the whole process, shared by every thread and every library in it. properpin's module needs the helper's exit code: 0 means yes, 1 no, anything else refuse. Four kinds of host break that, or are broken by it:

- **A host that ignores SIGCHLD.** With SIGCHLD set to "ignore", the kernel reaps children by itself and throws their exit codes away. The module would get "no such child", treat it as an error and refuse the PIN, every time: fail closed, but the PIN would never work in such a host. `ask_helper` guards against this the way pam_unix does around `unix_chkpwd`: `DefaultSigchld::set()` puts SIGCHLD back to its default before the helper starts and restores what it found afterwards. No test has ever run in a host that ignores SIGCHLD.
- **A host that reaps every child.** A SIGCHLD handler that calls `waitpid(-1)` collects any child that exits, the helper included, possibly before the module does. Same symptom as above, but at random. The guard also covers this, since the handler can't run while SIGCHLD is at its default. It doesn't cover a host thread that loops on `waitpid(-1)` without any handler: that thread steals the exit code whatever the setting.
- **The host being broken by properpin.** While the guard has SIGCHLD at its default, the host's own children can exit without the host being notified. A host that relies on its handler to reap them would then leave zombies, or miss that a child finished. pam_unix does exactly the same around `unix_chkpwd`, so a PAM host has to live with it, but nobody has checked that this host does.
- **Two threads at once, in 6.7.5.** If two authenticators run at the same time and both save, change and restore SIGCHLD, the classic race can lose the host's setting for good:

  | Step | Thread | What happens |
  |---|---|---|
  | 1 | A | saves the host's handler H, sets the default |
  | 2 | B | saves the default, sets the default |
  | 3 | A | restores H |
  | 4 | B | restores the default; H is gone for the rest of the greeter's life |

  properpin and pam_unix run one after the other on the same thread, so they can't race each other. Whether the fingerprint or smartcard stacks contain a module that does the same dance on another thread is unverified; on Fedora they are built around `pam_fprintd` and smartcard modules, not pam_unix. In 6.8 each authenticator has its own process, so this race can't happen there.

### One session, many attempts

- **libpam clears the typed text after every attempt.** `_pam_sanitize`, called at the end of `pam_authenticate` (`libpam/pam_misc.c`, read for `docs/kscreenlocker-pam-contract.md`), clears `PAM_AUTHTOK`, so a reused session can't hand one attempt's input to the next. properpin's module keeps no memory of its own between attempts.
- **What is untested is the lifecycle around that.** The second attempt on a session must ask for the PIN again rather than find something left over. The module must keep working across many attempts while loaded once (it is never unloaded, thanks to `-z nodelete`). `pam_setcred` after a success must be harmless (`pam_sm_setcred` returns `PAM_IGNORE`).
- **A panic must not leave SIGCHLD changed.** The guard restores SIGCHLD when it is dropped, which also happens while a panic unwinds, and the entry points turn a panic into `PAM_IGNORE`. The existing panic test (`test_panic`) panics before the guard is even set, so the restore-on-panic path has never run.

### Killed attempts, in 6.8

- **The helper outlives a killed worker.** `PR_SET_PDEATHSIG` isn't inherited across `fork`, and the kernel clears it anyway when a setgid program starts. So when the greeter kills the worker, the helper keeps running alone, finishes its check, writes its counts and exits, and the system reaps it. For counting that is good: a guess that reached the helper is recorded even if the attempt was cancelled. A correct PIN whose attempt was cancelled still resets the failures in a row and forgives the budget's recent failures, which only someone who knows the PIN can cause.
- **None of it is tested.** A killed attempt must never unlock. The count must stay saved. No helper may hang, and none does as long as its own one-second lock timeout holds. The next worker must get the lock within that second. The deferred randomized kill test in `docs/plan.md` was written for exactly this and needs the long-lived worker described below.

### Crashes at exit go unnoticed

The 6.8 worker ends its PAM session and then exits, which runs thread-local destructors after `pam_end`: exactly what crashes a Rust PAM module that has been unloaded. properpin links with `-z nodelete` and `stack.rs` reproduces the crash without it, but only for threads that exit, not for a process that exits after `pam_end`. The container test doesn't look at how its attempt processes ended, so a crash at exit would still pass. The real greeter would see its worker die after every attempt.

## What the work would be

### In `pamharness`

- **A session object** that keeps one PAM handle and runs any number of attempts on it, as both kscreenlocker versions do, with the conversation answering each prompt from a queue of inputs.
- **`pam_setcred(PAM_REFRESH_CRED)` after every success,** errors ignored, as kscreenlocker does.
- **A `PAM_FAIL_DELAY` callback** that records the requested delay instead of sleeping. Tests get faster, and they can assert that a wrong PIN asked for a delay. What protects the PIN is the failure limit, not the delay, so not sleeping changes nothing the tests prove.

### In `stack.rs`: hosts that misbehave

Each variant runs attempts through the real libpam with properpin's lines, and checks the answers and the host's state afterwards:

- **SIGCHLD ignored** for the whole test process: the PIN must still work, and SIGCHLD must still be "ignore" afterwards.
- **A handler that reaps every child,** installed before the attempts: the PIN must still work, the handler must be back afterwards, and it must not have reaped the helper.
- **A thread that loops on `waitpid(-1)`:** expected to fail closed today (the PIN refused, the password still working). The test documents the behaviour rather than demanding success, unless the design changes as described below.
- **The host's own child exiting during an attempt:** the host starts a child that exits while the helper runs, and must still be able to collect its exit code afterwards.
- **Attempts on several threads at once,** each with its own session, while another thread keeps a SIGCHLD handler installed: every answer right, and the handler still installed at the end.
- **A panic inside the guard's window,** through a test-only point placed after `DefaultSigchld::set()`: SIGCHLD restored, the answer `PAM_IGNORE`, the password still working. This one needs care, since nothing test-related should go into the shipped module; the existing `test_panic` argument is the precedent, and the alternative is to unit test the guard on its own.

### In the container: a worker like 6.8's

- **A long-lived attempt process** that reads a stream of inputs and runs them as attempts on one session, like `kscreenlocker_worker`, logging each result.
- **Killed at chosen points and at random,** with SIGTERM and with SIGKILL. Afterwards: no unlock happened, the counts and the budget parse and never went down, no helper is left running past its timeout, and a fresh worker gets the lock within a second. This is the first step of the deferred kill test.
- **Every attempt process checked for a clean exit,** an exit code and not a signal, in every scenario, not just this one.

### Checks on every run

- the right answer, every time;
- no zombie helper left behind;
- the host's SIGCHLD setting exactly as it was before;
- the host's own children still reapable by the host;
- the time a correct PIN takes through the real stack, now an assertion that it is at least `min_milliseconds_before_pin_unlock`, 75 ms by default.

## What it is likely to find, and the fix

Most of it should pass: the guard is the same one pam_unix has used for years, and the module keeps no state between attempts. The likeliest failures are the thread that reaps every child, which fails closed by design today, and the race between two threads saving and restoring SIGCHLD.

The cleanest fix for both would stop the answer from depending on SIGCHLD at all. The helper would also write its answer, "yes" or "no", to a pipe the module created and only the helper can write to; the module would trust that, and treat the exit code as a second opinion. Reaping the helper would then only clean up, and could fail without changing the answer. The save, change and restore of SIGCHLD could go, and with it the race and the side effect on the host's own children. The helper already writes to stdout for `status`, so the protocol change is small, but it is a change to what ships and to the helper's review checklist, so it should wait until a test shows it is needed.

## What it can't replace

The real greeter stays for the VM: the QML, the D-Bus traffic between greeter and worker, the eager start of attempts in 6.8, the `pendingPassword` path that can trip the 50 ms check, SELinux and logind. This work makes sure that whatever the VM finds is about those, and not about lifecycle bugs that could have been caught in seconds on the development machine.

## Effort and order

Small to medium, almost all test code. A sensible order:

- the session object and `pam_setcred` in `pamharness`, which every other part uses;
- the misbehaving hosts in `stack.rs`, fastest to write and likeliest to find something;
- the clean-exit check in the container, a few lines;
- the long-lived worker and its kills, which grows into the deferred kill test;
- the timing measurement, together with the minimum-duration row.
