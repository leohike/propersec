# lazypass -- the short_password, a short password for the KDE lock screen.
# deploy installs the code and /etc/lazypass with sudo, but never edits /etc/pam.d/kde. Only
# deploy-pam and restore-pam write that file, each after showing the diff and asking. test-all
# writes to the journal. See README.md and INTEGRATION.md.
#
# System python3 and the stdlib only, deliberately: the hook runs inside the lock screen's PAM
# stack, where a project virtualenv has no business being.

lazypass_dir := source_directory()

# Run the tests (all in temporary directories; real libpam and pam_exec, fake pam_unix)
test *args:
    @cd {{ lazypass_dir }}/src && python3 -B -m unittest discover -s tests -t . {{ args }}

# The two PAM tests that make pam_exec log to the system journal, plus everything else
test-all *args:
    @cd {{ lazypass_dir }}/src && LAZYPASS_TESTS_MAY_LOG=1 python3 -B -m unittest discover -s tests -t . {{ args }}

# Run the tests, then install the code and /etc/lazypass with sudo (never /etc/pam.d/kde), check, smoke-test
deploy: test
    sudo /usr/bin/python3 -I {{ lazypass_dir }}/deploy.py install
    /usr/bin/python3 -I {{ lazypass_dir }}/deploy.py check
    /usr/bin/python3 -I {{ lazypass_dir }}/deploy.py smoke

# Every deployed path: present, owner, mode, content same as src/, SELinux label. No root needed
check-deploy:
    @/usr/bin/python3 -I {{ lazypass_dir }}/deploy.py check

# Run the deployed copy as yourself: hook self-test ("hello lazypass"), hook refusing outside PAM, `lazypass status`
smoke:
    @/usr/bin/python3 -I {{ lazypass_dir }}/deploy.py smoke

# Activate lazypass: install pam/kde as /etc/pam.d/kde, after a diff and a yes (sudo inside). Keep a root TTY open
[arg("force", short="f", value="--force")]
deploy-pam force="":
    /usr/bin/python3 -I {{ lazypass_dir }}/deploy.py install-pam {{ force }}

# Rebuild pam/kde from the image's /usr/etc/pam.d/kde plus pam/kde-auth.pam; changes only the repo
render-pam:
    @/usr/bin/python3 -I {{ lazypass_dir }}/deploy.py render-pam

# Copy /etc/pam.d/kde to backup/kde. An existing, different backup is kept, never overwritten
backup-pam:
    @/usr/bin/python3 -I {{ lazypass_dir }}/deploy.py backup-pam

# The file given defaults to backup/kde; /usr/etc/pam.d/kde is the image's vendor copy.
# A relative path is taken from where you run just. -f writes even when the files already match.
# Put a backup back as /etc/pam.d/kde, after showing the diff and asking (sudo inside)
[no-cd]
[arg("force", short="f", value="--force")]
restore-pam force="" backup="":
    @/usr/bin/python3 -I {{ lazypass_dir }}/deploy.py restore-pam {{ force }} {{ backup }}
