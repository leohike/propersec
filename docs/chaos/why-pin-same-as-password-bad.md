# Why a PIN equal to the password is bad

Written on 2026-10-17. `set` refuses a PIN that is exactly the password, but the two can still end up equal: the comparison is skipped for users with no entry in `/etc/shadow` (LDAP, systemd-homed), and nothing notices a password changed to the PIN later. Then three things go wrong.

## The lock screen loses its password path

screenlock-pin's PIN line comes first in `/etc/pam.d/kde`, and a match ends the stack. While the PIN is enabled, the password is always taken as the PIN, so `pam_unix`, the PIN unpause and the stock `password-auth` lines never run at the lock screen. Anything that needs to see the password there never gets it, such as `pam_systemd_home` unlocking a home directory again. With a different PIN, the user can type the password instead; here they can't.

## A leaked password survives the password change

When the password leaks and the user changes it, the old one still unlocks the lock screen, within the failure limits, until `screenlock-pin set` or `remove`. Any leaked PIN behaves the same way, but here the user doesn't think of it as a PIN, so nothing reminds them to change it.

## The password hash becomes readable by the PIN checker's group

`/etc/shadow` needs root; the PIN file needs only the `screenlock-pin` group, which an exploit of the setgid PIN checker gives to any local user. With several users, bob could then read alice's PIN hash, which is her password, and crack it offline, as easily as the hash in `/etc/shadow` he could never read. He gets her login and `sudo`, not just her lock screen. This is the one way screenlock-pin with such a PIN is strictly worse than no screenlock-pin at all.

## Left at that

Decided on 2026-10-17: beyond refusing an exact match at `set`, screenlock-pin only says, when it asks for the PIN, that it should differ from all the user's account passwords. Catching a later password change would mean asking `unix_chkpwd` after correct PINs, which is too much machinery for a user's own choice.
