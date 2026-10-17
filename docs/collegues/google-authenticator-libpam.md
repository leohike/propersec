# google-authenticator-libpam: what its README says about installing and editing PAM files

Repository: https://github.com/google/google-authenticator-libpam, cloned to /var/home/shared/projects/pam-related/google-authenticator-libpam. Read at commit 288db94951a9c93960a20cfd0d72359813ccc909 (2026-02-27); the README last changed in 8c021af (2022-02-04).

README path in that repo: `README.md`.

## Verdict

Installing is `sudo make install`, which puts the module in `$(libdir)/security` (`Makefile.am:4`) and writes nothing to `/etc/pam.d`. Getting it into a stack is left to the admin: "Add this line to your PAM configuration file", without saying which file, and with advice on control values (`required`, not `requisite`) and on adding `pam_permit.so` when `nullok` is used. There is no lockout warning and no installer or helper for the edit.

## Installation and PAM setup, verbatim (README.md lines 17-43)

```
17	## Build & install
18	```shell
19	./bootstrap.sh
20	./configure
21	make
22	sudo make install
23	```
24	
25	If you don't have access to "sudo", you have to manually become "root" prior
26	to calling "make install".
27	
28	## Setting up the PAM module for your system
29	
30	For highest security, make sure that both password and OTP are being requested
31	even if password and/or OTP are incorrect. This means that *at least* the first
32	of `pam_unix.so` (or whatever other module is used to verify passwords) and
33	`pam_google_authenticator.so` should be set as `required`, not `requisite`. It
34	probably can't hurt to have both be `required`, but it could depend on the rest
35	of your PAM config.
36	
37	If you use HOTP (counter based as opposed to time based) then add the option
38	`no_increment_hotp` to make sure the counter isn't incremented for failed
39	attempts.
40	
41	Add this line to your PAM configuration file:
42	
43	`  auth required pam_google_authenticator.so no_increment_hotp`
```

## Further edits the README asks for, verbatim (README.md lines 66-79 and 176-181)

```
66	During the initial roll-out process, you might find that not all users have
67	created a secret key yet. If you would still like them to be able to log
68	in, you can pass the "nullok" option on the module's command line:
69	
70	`  auth required pam_google_authenticator.so nullok`
71	
72	## Encrypted home directories
73	
74	If your system encrypts home directories until after your users entered their
75	password, you either have to re-arrange the entries in the PAM configuration
76	file to decrypt the home directory prior to asking for the OTP code, or
77	you have to store the secret file in a non-standard location:
78	
79	`  auth required pam_google_authenticator.so secret=/var/unencrypted-home/${USER}/.google_authenticator`
176	
177	PAM requires at least one `SUCCESS` answer from a module, and `nullok`
178	causes this module to say `IGNORE`. This means that if this option is
179	used at least one other module must have said `SUCCESS`. One way to do
180	this is to add `auth required pam_permit.so` to the end of the PAM
181	config.
```
