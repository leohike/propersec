# Uninstall should purge the PIN hashes

A requirement for later, written on 2026-10-03. The plan row "Purge the PIN hashes on uninstall" in `docs/chaos/plan.md` points here.

`install.sh uninstall` keeps `/etc/screenlock-pin`, `/var/lib/screenlock-pin` and the `screenlock-pin` group, so that installing again brings everyone's PIN back. Keeping the config and the budgets is fine: they are small and hold nothing secret.

The PIN hashes in `/etc/screenlock-pin/users/` are different. Once screenlock-pin is gone, nothing uses them, yet they stay on disk. Backups and disk images keep copying them, and a PIN is often reused elsewhere, such as a phone or a bank card. A hash of a 4-digit PIN falls to an offline attacker in minutes, as `docs/chaos/threat-insider-hash-leak.md` explains. An uninstalled product should not leave that behind.

So uninstall should always delete the user files with the hashes, even when it keeps everything else, and say so. A user who reinstalls sets their PIN again with `screenlock-pin set`. The kept copy of `/etc/pam.d/kde` from enable, and `kde.pam.damaged` if uninstall made one, can stay.

When this is done, the uninstall cases (`crates/systest/src/uninstall.rs`) should check that no file under `/etc/screenlock-pin/users/` survives uninstall, instead of allowing all of `/etc/screenlock-pin` as a leftover.
