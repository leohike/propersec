# pam-u2f: what its README says about installing and editing PAM files

Repository: https://github.com/Yubico/pam-u2f, cloned to /var/home/shared/projects/pam-related/pam-u2f. Read at commit b5846bb74f9f9871c14adb986516817f546f8096 (2025-03-27); the README last changed in 4e7edd4 (2025-03-14).

README path in that repo: `README` (AsciiDoc; `README.adoc` is a symlink to it).

## Verdict

Installing puts only the module in place, through a distro package or `make install` / `cmake --install`; nothing in the build writes to `/etc/pam.d` (`Makefile.am:33` installs the plugin to `$(PAMDIR)`, the PAM module directory set in `configure.ac:55-67`). Getting it into a stack is left to the admin: "Create a file for a new service in `/etc/pam.d/` or edit an already existing one by adding a line". The README warns that a wrong edit can lock users out and tells the admin to keep a root shell open, the same advice install.sh gives before writing `/etc/pam.d/kde`.

## Installation, verbatim (README lines 16-46)

```
16	== Installation
17	
18	pam-u2f comes readily packaged for a number of systems. A non-exhaustive
19	list is available below.
20	
21	=== Ubuntu
22	
23	----
24	# apt install libpam-u2f pamu2fcfg
25	----
26	
27	Additionally, Yubico maintains a PPA with up-to-date versions of pam-u2f.
28	
29	----
30	# apt install software-properties-common
31	# apt-add-repository ppa:yubico/stable
32	# apt update
33	# apt install libpam-u2f pamu2fcfg
34	----
35	
36	=== Fedora
37	
38	----
39	# dnf install pam-u2f pamu2fcfg
40	----
41	
42	=== macOS
43	
44	----
45	$ brew install pam-u2f
46	----
```

## Installing a build from source, verbatim (README lines 76-81 and 170-174)

```
76	Once the module is built, copy the file `pam_u2f.so` to the correct
77	directory for your system. Typically `/lib/security/` or
78	`/lib/x86_64-linux-gnu/security/`. This is automated by `make install`
79	assuming that the pam directory chosen by `configure` is correct. If
80	that is not the case it can be specified with
81	`./configure --with-pam-dir=`.
170	The obtained artifacts can be installed as follows:
171	
172	----
173	# cmake --install .
174	----
```

## Editing PAM files, verbatim (README lines 176-193)

```
176	== Service Configuration
177	
178	Create a file for a new service in `/etc/pam.d/` or edit an already
179	existing one by adding a line similar to this:
180	
181	----
182	auth sufficient pam_u2f.so debug
183	----
184	
185	For more information about the syntax of PAM configuration files, please
186	see the manual page for pam.conf(5). Additional <<examples,example
187	configurations>> can be found below.
188	
189	IMPORTANT: An erroneous PAM configuration may lock some or all users
190	out of the system or prevent you from gaining root privileges. It is
191	recommended that you start a separate shell with root privileges while
192	configuring PAM to be able to revert changes if something goes wrong.
193	Test your configuration thoroughly before closing the root shell.
```

## Example lines the admin is to insert, verbatim (README lines 342-380)

```
342	[[examples]]
343	=== Example Service Configurations
344	
345	==== Second Factor Authentication
346	
347	Configure pam-u2f as a `required` module after your primary authentication
348	module(s) for use as a second factor. Make sure that the primary authentication
349	method is not `sufficient` or uses other control values that may preempt
350	execution of pam-u2f.
351	
352	----
353	# Primary authentication method(s) above this line.
354	auth required pam_u2f.so authfile=/etc/u2f_mappings cue
355	----
356	
357	==== Passwordless Authentication
358	
359	For a passwordless experience, where the authenticator PIN can be used in place
360	of the user password, you can insert the below line towards the top of your
361	service configuration. You may need to change the control value to something
362	else if you'd like to execute additional authentication modules after pam-u2f.
363	
364	----
365	auth sufficient pam_u2f.so authfile=/etc/u2f_mappings cue pinverification=1
366	# Fallback modules go below this line (e.g. password authentication).
367	----
368	
369	==== Passwordless Authentication using Biometrics
370	
371	Similar to the previous configuration but capable of built-in user
372	verification, e.g. fingerprint matching using the YubiKey Bio. This example
373	falls back to using PIN verification if the fingerprint does not match or is
374	otherwise blocked.
375	
376	----
377	auth sufficient pam_u2f.so authfile=/etc/u2f_mappings cue pinverification=0 userverification=1
378	auth sufficient pam_u2f.so authfile=/etc/u2f_mappings cue pinverification=1 userverification=0
379	# More fallback modules go below this line (e.g. password authentication).
380	----
```
