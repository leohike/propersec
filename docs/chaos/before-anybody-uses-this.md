# Before anybody uses this

What has to happen before properpin is offered to anyone but its author, written on 2026-10-15, the day of the first install on a real KDE (`docs/chaos/aurora-vm-test.md`). Documentation and a website are taken for granted and left out; this is everything else: legal, security process, testing, code, packaging, CI, integration with upstream, and outside review. It draws on the plan, the open concerns, the tooling notes, the Aurora VM report and some reading on how open-source security tools are usually brought to users. `docs/chaos/plan.md` stays the list of engineering work; this file is the gate in front of other people's machines, and items that turn into work should become rows there.

## Where things stand

The engineering is further along than the project's outward face. The PAM module is tested through the real libpam the way kscreenlocker drives it, the setgid pinchecker is attacked as root and as other users in a container, 13 deliberately broken builds check that one uninstall repairs the system, mutation testing runs weekly, the threat model is written down in `docs/chaos/security-target.md`, and the PIN now works at a real Plasma 6.7.5 lock screen under SELinux enforcing. What is missing is almost everything a stranger needs in order to use it safely: permission to use it at all, a way to report a hole, a package instead of a cargo build, a tested way back out, and somebody other than the author having looked at the pinchecker.

## Blockers

Nobody else installs properpin until each of these is done.

### A licence

There is no `LICENSE` file, so the code is all rights reserved: nobody may legally use, modify or redistribute it, whatever the repository's visibility. Pick one and add it, with SPDX headers or at least the `license` field in the workspace `Cargo.toml`. Linux-PAM is BSD-3-Clause or GPL; most PAM modules and lock screen code are GPL-2.0-or-later or LGPL, and most Rust code is MIT or Apache-2.0. GPL-2.0-or-later fits the PAM and KDE world and keeps changes open; MIT or Apache-2.0 makes it easiest for KDE or a distribution to take the code in. Whichever it is, `deny.toml`'s licence check should then be made to fail, so no dependency with an incompatible licence slips in.

### A private way to report a vulnerability

A setgid pinchecker and a module inside the lock screen are exactly what people will probe. Add a `SECURITY.md` that says which versions are supported, how to report (GitHub's private vulnerability reporting, turned on in the repository settings, and an email address), what reply time to expect, and how fixes and advisories are published. Decide beforehand how a fix reaches users: a new release, a GitHub security advisory, a CVE through GitHub's CNA if it is serious. Without this, the first person who finds a hole either posts it in a public issue or tells nobody.

### Recovery, written for users and tested

The worst thing properpin can do is lock its user out of their own lock screen: a module libpam can't load fails the whole `kde` stack, the right password included, as the Installing part of `docs/chaos/concerns.md` says. The repair exists (a TTY or SSH, then `install.sh uninstall`, which restores `/etc/pam.d/kde`) but is described only in test documents. Users need a short page, read before installing, that says:

- make sure you can reach a text console (Ctrl+Alt+F3) or SSH in before you install it, and that you know your password there;
- keep a copy of `/etc/pam.d/kde` from before, and where `install` keeps its own (`/etc/properpin/kde.pam.without-properpin`);
- the one command that takes properpin out, and the one line to delete from `/etc/pam.d/kde` by hand if even that is not possible;
- on an atomic desktop, that `ostree admin config-diff` shows what changed in `/etc`, and that an older deployment can be booted.

The repair from a text console should then actually be done in the VM, as `docs/chaos/uninstall-test-remaining-ideas.md` already asks, so the page describes something that was tried.

### Uninstall on a real system

`install.sh uninstall`, and `install` over an earlier install, were never run outside a container: not their interactive diff and prompt, not the relabelling of the restored PAM file, not the leftovers on an ostree system. It is the first item under "What remains untested on a real system" in the Aurora VM report and the cheapest blocker to clear: snapshot the VM, uninstall, check `ausearch` and the file list, compare `/etc/pam.d/kde` with the saved copy.

### Purge the PIN hashes on uninstall

Already a row in the plan and described in `docs/chaos/uninstall-should-purge-pin-hashes.md`. Before anyone else has hashes on disk, uninstall should delete them, so they don't live on in backups and disk images after the user thinks properpin is gone. A four-digit PIN behind a leaked hash falls in seconds, and PINs are reused on phones and cards.

### kscreenlocker 6.8

6.8 changes the very thing properpin depends on most: each attempt runs in a worker process that the greeter kills on cancel, and every `pam_authenticate` is timed against 50 ms. The container imitates this, and the minimum duration before a PIN unlock was built for it, but nothing has run under the real 6.8 greeter. On Aurora it will arrive silently with an image update, under a `/etc/pam.d/kde` that properpin already edited. Before users:

- recheck the code against the tagged 6.8.0, as the plan's row says;
- run the VM test again on 6.8: the "ms elapsed during pam_authenticate" journal lines, a PIN typed during the failure delay, suspend while an attempt runs, fingerprint and smartcard switching;
- run an ostree image update with properpin enabled, before and after, as the Aurora VM report lists;
- decide whether `check` and `install` should warn, or refuse, on a kscreenlocker version properpin was never tested with. A refusal is safer; a warning is friendlier to users on distributions that move faster than the tests. Either way the supported versions belong in the README.

### Supported systems, stated and enforced

Only Fedora 44 (in a container) and Aurora 44 (in a VM) have run properpin. Debian, Ubuntu and their derivatives build the stack from `common-auth`, Arch from `system-local-login` and friends, openSUSE differently again, and `install.sh install` expects Fedora's `auth substack password-auth` followed by `auth include postlogin`. `install` should refuse any `/etc/pam.d/kde` it doesn't recognise, with a message naming the supported systems, and the README should list them. Users on other distributions will try anyway; the refusal is what keeps a guess from turning into a lock-out.

## Decide now, while nobody depends on it

These get much more expensive once anyone has properpin installed, because every change then needs a migration.

### The pinchecker protocol

`docs/chaos/concerns.md` notes, under the PAM module's side, that reading the pinchecker's answer from a pipe instead of from its exit code would remove the process-wide SIGCHLD guard, its mutex, and the three remaining races with other threads and modules, at the cost of a protocol change. Today the module and the pinchecker ship together from one tree and nobody has either installed, so the change costs one commit. After a release, a new module talking to an old pinchecker (or the reverse, between a package update and a re-lock) becomes a case to handle. Decide it now, and whatever the answer, put a protocol version into the exchange so a mismatch fails closed with a clear log line.

### Versioned file formats

The user file, the per-boot state and the budget are `key = value` files without a version. A damaged or unknown file refuses the PIN, which is safe, but a future format change would then refuse every user's PIN until `set` runs again, and nothing would say why. A `format = 1` line in each, checked on read, lets a later version migrate or explain.

### One name

The root README is still headed "lazypass" with "TBD…", the repository is propersec, the product is properpin, and the Python proof of concept is called lazypass too. Settle the names (propersec the family, properpin the product, presumably) and rewrite the root README before any website, search result or package name fixes them.

### Settings and defaults that are hard to change later

A default users never touch becomes a promise. Before a release, decide the open ones in the plan: the default `hash_cost` (5 today, 8 measured to be fine), the limits of the failure budget, and whether fingerprint and smartcard unlocks unpause the PIN (the plan's row says it should be a stated decision, not an accident).

## Testing still to do

On top of 6.8 and uninstall, from the Aurora VM report's list of what remains untested on a real system, these matter before strangers rely on it:

- **The PIN disabled by the budget,** then refused after the password, and `sudo properpin enable` bringing it back, at the real lock screen.
- **Suspend and resume** with the lock screen up, paused or not, since laptops sleep with the lock screen up far more often than they reboot.
- **A password change,** which should stop the PIN silently until the next `set`, and `properpin status` saying so.
- **Other services refusing the PIN** for real: polkit, SDDM, a TTY login and SSH, not only `sudo`.
- **More than one user with a PIN,** and a confined SELinux user (`user_t`, `staff_t`), where running a setgid program from `/usr/local/libexec` may be refused.
- **A build from the toolchain users will actually use,** with the test suite run on it. Today's build used Homebrew's Rust and its linkage was checked by hand; a packaged release removes that question, as described below.
- **Fuzzing,** the plan's next tooling step: cargo-fuzz targets for the settings, state and budget parsers and `decode_hash`, in CI. Once the targets exist, OSS-Fuzz can run them continuously for free.
- **The randomized kill test at scale,** a few hundred kills during the correct PIN and the password too, once 6.8's worker is the real thing users run.
- **The mutation testing backlog:** the pinchecker, which isn't mutated yet, and turning new survivors into a failing job.

Then the step no test replaces: **use it daily on the author's own machine for a few weeks,** through image updates, suspend, external monitors, a forgotten PIN and a changed password, and note every surprise. After that, a small group of testers who are comfortable with a TTY and SSH, told plainly that it is a beta, with the recovery page in hand.

## Packaging and releases

Today the only way to install properpin is to clone the repository, build with cargo and copy files into `/usr/local`. For a stranger that is the riskiest step of all: the Aurora build showed that a Homebrew toolchain could link the setgid pinchecker and the module against libraries in a directory the user can write to, which would hand the user code running with the pinchecker's group or inside the greeter. It came out clean, but only because it was checked by hand, and no user will check it.

- **Releases.** Semantic versions with git tags, a CHANGELOG that calls out security fixes, and release artifacts built only by CI, never on a laptop. Sign the tags.
- **Provenance.** GitHub's artifact attestations give each release a signed record of which workflow built it from which commit, in the SLSA style, at no cost. A reproducible build (two independent builds, byte-identical output) is the stronger version and worth trying once the build is packaged.
- **An RPM, in COPR.** On Fedora this is the natural channel, and on atomic desktops (Kinoite, Aurora, Bazzite) users can layer it with `rpm-ostree install`, after which it lives in `/usr` with the distribution's SELinux labels and survives image updates. Layering is meant for system software exactly like this. The package would install the files and the group; the edit to `/etc/pam.d/kde`, which `install.sh install` makes, should stay a command the user runs, never an RPM scriptlet, so a package install can never by itself change how the lock screen authenticates. That command would also have to take the lines out before a package update and put them back after, as `install.sh install` does. Removal of the package should refuse, or take the lines out first, while the PAM file still names the module, because otherwise it would delete a module the stack still loads, which is the lock-out described above.
- **Image builders.** Aurora and other Universal Blue images are often customised with a containerfile; a short recipe for adding properpin's RPM to a custom image would reach exactly the people most likely to want this.
- **Later,** a systemd-sysext image for atomic systems without layering, and packages for other distributions once their PAM layouts are supported.

## CI and the repository

CI already runs the tests on Fedora 44 and on the declared Rust version, clippy and rustfmt, the podman system test, the dependency audit, and weekly mutants, with every action pinned to a commit. What is left is mostly about protecting the repository itself, since whoever can push to `main` can ship code into users' lock screens:

- **Protect `main`:** required status checks, no force-pushes, no deletion, and changes through pull requests even when the author is the only reviewer, so CI always runs before anything lands. Turn on two-factor authentication for every account with write access.
- **OpenSSF Scorecard,** as a GitHub Action. It checks branch protection, workflow permissions, pinned dependencies, signed releases, a security policy and more, and much of it properpin already meets; the rest is a ready-made to-do list. The OpenSSF Best Practices badge is a similar self-assessment that users and distributions recognise.
- **`shellcheck` for `install.sh`** and the podman scripts, tabled in `docs/chaos/tooling-remaining-ideas.md`. `install.sh` runs as root and edits PAM; it is the most dangerous file the project ships after the pinchecker.
- **`cargo-deny` failing on licences, bans, duplicates and sources,** already a plan row, and natural to finish together with choosing the licence.
- **A release workflow** that builds, tests, packages and attests, triggered by a signed tag.
- **The VM test, scripted.** Today's Aurora test was done by hand over an afternoon. A script that boots a snapshot of an Incus VM, installs a build, runs what can be run without a human (the pinchecker, `install.sh check`, `ausearch`, the journal, a reboot, uninstall) and leaves the lock screen part as a short manual checklist, would make it cheap enough to repeat for every release and every new kscreenlocker. Driving the real greeter headless is possible in principle (kscreenlocker_greet has a testing mode) but is a project of its own.
- **Update the product README's CI section,** which still says clippy and rustfmt aren't in CI.

## Upstream and integration

- **Talk to KDE.** properpin depends on details of kscreenlocker that nobody promised to keep: one prompt per attempt, the PIN and the password in the same field, the new 50 ms check. A post on KDE Discuss, or an issue on kscreenlocker's GitLab, describing what properpin assumes (`docs/chaos/kscreenlocker-pam-contract.md` is most of it already), gets expert review of those assumptions and a chance of hearing about the next change before it ships. KDE may also have opinions on a PIN feature, or want one of their own; better to know early.
- **Linux-PAM and pam_unix.** The pinchecker copies `unix_chkpwd`'s pattern closely; the Linux-PAM maintainers are the people best placed to say where the copy differs in a way that matters.
- **Fedora's SELinux policy.** If confined users turn out to need a policy module for the pinchecker or its directories, the selinux-policy maintainers can say whether a module of properpin's own or a change upstream is the right fix.

## Outside review

Everything so far has been reviewed by its author, with the help of an AI assistant. For a program that runs with more rights than its caller and reads every PIN hash on the machine, that is not enough before others trust it. `docs/chaos/concerns.md` itself flags the `--dev` guard as "worth a second reviewer's look", and `docs/chaos/pinchecker-review.md` is a ready-made checklist for a reviewer.

- **A professional audit** of the pinchecker and the PAM module is the gold standard. OSTIF organises audits for open-source projects, but mostly for projects judged critical, and its AWS-funded audits averaged about $74,000 each, which gives a sense of the cost. The Linux Foundation's crowdfunding platform has a fund type for paying for an OSTIF audit.
- **NLnet's NGI Zero grants** are the realistic route for a small European-style FOSS project: besides funding work, NLnet offers its grantees support that has included security audits (by Radically Open Security), accessibility and packaging help. Worth confirming the current terms and applying; properpin's scope, a privilege-separated pinchecker in a few thousand lines of Rust, is well within what such an audit covers.
- **Informal review,** at the least: ask on the oss-security mailing list, in Rust security and PAM circles, or of a security engineer you know, to read the pinchecker's `main.rs`, `secure.rs` and `lib.rs` against the review checklist. The pinchecker is small; an afternoon of an experienced reader's time is worth more than another week of tests.

Publish whatever reviews happen, with the fixes, in the repository.

## For users, beyond documentation

- **An honest one-page summary of what properpin protects and what it doesn't,** for people who won't read `docs/chaos/security-target.md`: it assumes full-disk encryption and no unencrypted swap or hibernation, someone watching you type can still catch the PIN, four digits are weak and two random words are not, and root wins either way.
- **Issue templates** that ask for the distribution and version, the kscreenlocker version, the output of `sudo install.sh check` and the journal lines from `properpin-pinchecker`, `pam_unix` and `kscreenlocker_greet`, and that send anything security-related to `SECURITY.md` instead.
- **A clear beta label** in the README and on the release page until outside review and the 6.8 test are done.

## The shortest version

If only five things happen first: a licence and a `SECURITY.md`; recovery and uninstall tested on a real system and written for users; a real test on kscreenlocker 6.8; signed packages built by CI instead of cargo builds on users' machines; and one person who isn't the author reviewing the pinchecker.

## Sources

- OSTIF independent security audit impact report: https://ostif.org/the-ostif-independent-security-audit-impact-report/
- Why OSTIF: https://ostif.org/why-ostif/
- Linux Foundation crowdfunding for projects: https://crowdfunding.linuxfoundation.org/for-projects
- An OpenSSF Best Practices baseline entry: https://www.bestpractices.dev/projects/12767/baseline-2
- Layering packages with rpm-ostree (Bazzite documentation): https://docs.bazzite.gg/Installing_and_Managing_Software/rpm-ostree/
- COPR on OSTree systems: https://www.github.com/34N0/rpm-copr
- Local package layering with bootc: https://gitlab.com/fedora/bootc/tracker/-/issues/4
- NLnet NGI Zero: https://nlnet.nl/
