# fprintd: what its README says about installing and editing PAM files

Repository: https://gitlab.freedesktop.org/libfprint/fprintd, cloned to /var/home/shared/projects/pam-related/fprintd. Read at commit 5731b9a94bbd50d4cc2bc0644affb3eb2be321fc (2026-10-16).

README paths in that repo: `README` (the top-level one) and `pam/README` (the PAM module's own).

## Verdict

The top-level `README` says nothing about installing or about PAM files beyond "A PAM login module is included in the 'pam' directory." (line 13). The instructions are in `pam/README`, written once by Bastien Nocera in c1ec850 (2008-11-25, "Add README for the PAM module") and never changed since: "Modify the appropriate PAM configuration file (/etc/pam.d/system-auth-ac on Fedora systems), and add the line". `system-auth-ac` was the authconfig-era file name; Fedora has used authselect, which owns `system-auth`, for years, so the one concrete path it gives is stale. The build installs only the module, into the PAM module directory (`pam/meson.build:8-11`, `37-38`), and nothing into `/etc/pam.d`. The same file's known issues end with the idea that login managers should "run 2 separate PAM stacks", which is the design GDM and kscreenlocker later adopted.

Caveat for the framing in docs/check-collegues.md: fprintd's upstream does ask the admin to edit by hand, but distributions don't leave it there. Fedora enables it through authselect's `with-fingerprint` and Debian through a pam-auth-update profile, as docs/analysis/gdm-fprintd.md explains.

## Top-level README, verbatim (README lines 1-13)

```
1	fprintd
2	=======
3	
4	https://fprint.freedesktop.org/
5	
6	Daemon to offer libfprint functionality over D-Bus
7	Might eat your kangaroo.
8	
9	Written in C.
10	
11	Licensed under the GPL version 2 or any later version (see COPYING).
12	
13	A PAM login module is included in the 'pam' directory.
```

## pam/README, verbatim (whole file)

```
1	PAM module for fingerprint authentication
2	-----------------------------------------
3	
4	Using:
5	* Modify the appropriate PAM configuration file
6	(/etc/pam.d/system-auth-ac on Fedora systems), and add the line:
7	auth        sufficient    pam_fprintd.so
8	before the line:
9	auth        sufficient    pam_unix.so ...
10	* You can now enroll fingerprints using fprintd-enroll. The first available
11	  fingerprint available will be used to log you in.
12	
13	Options:
14	* You can add the "debug" option on the pam configuration file line above,
15	  this will log more information from PAM to the file specified in your
16	  syslog configuration (/var/log/secure by default on Fedora)
17	
18	Known issues:
19	* pam_fprintd does not support identifying the user itself as
20	  that would mean having the fingerprint reader on for all the time
21	  the user selection is displayed, and could damage the hardware.
22	  It could be fixed by having gdm/login only start the PAM conversation
23	  when there is activity
24	* pam_fprintd doesn't support entering either the password or a fingerprint,
25	  as pam_thinkfinger does, because it's a gross hack, and could be fixed
26	  by having the login managers run 2 separate PAM stacks
```
