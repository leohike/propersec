use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::O_NOFOLLOW;
use properpin_core::{Budget, Error, HASH_SETTING, MAX_FILE_BYTES, Settings, Store, kv};

use crate::system;

/// How long an attempt waits for another one to finish with the budget. The lock screen must never
/// hang on properpin, so after this the attempt gives up and the password is checked instead.
const LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// One user's properpin files, and the rules for trusting each of them:
///
/// ```text
/// <etc>/config               global settings, optional            owner-only writable
/// <etc>/users/<user>         the user's settings and hash         owner:<pinchecker group> 0640
/// <budget_dir>/              every user's budget, on disk         owner:<pinchecker group> 1770
/// <budget_dir>/<uid>.budget  a Budget                             <uid>:<pinchecker group> 0600
/// <budget_dir>/<uid>.lock    serialises concurrent attempts       <uid>:<pinchecker group> 0600
/// ```
///
/// The settings and the hash must belong to `etc_owner`, so nobody else can change them: root once
/// installed, the test's own uid in tests. The hash must be readable by the pinchecker's group and
/// by nobody else, and the config by everyone, since the PAM module reads it as the user. The
/// pinchecker can't even open a file it can't read, so those rules matter to root, which reads
/// everything: `properpin doctor` judges every file by the same rules the pinchecker does, and
/// finds what an attempt would refuse. The budgets live in one directory for all users, which
/// only the pinchecker's group can enter, so a user can neither read nor reset their counts. The
/// directory is sticky, and each user's budget and lock files must belong to that user, so one
/// user's run of the pinchecker can't read or replace another's. Both are created by root, at
/// `properpin set` ([`UserFiles::start_budget`]), and given to the user; the pinchecker only opens
/// them, so nobody's run ever creates a file there that another user's could find in their name.
/// Whoever writes the budget, the user or root, gives it to the user. [`UserFiles::new`] gives the
/// `etc` side, which `properpin set` and `remove` need; [`UserFiles::with_budget`] adds the
/// budget.
#[derive(Debug, Clone)]
pub struct UserFiles {
    etc: PathBuf,
    etc_owner: u32,
    budget: Option<SharedDir>,
    user: String,
    uid: u32,
}

/// A directory every user's files share: owned by `owner`, with the pinchecker's `group`.
#[derive(Debug, Clone)]
struct SharedDir {
    path: PathBuf,
    owner: u32,
    group: u32,
}

impl UserFiles {
    pub fn new(etc: impl Into<PathBuf>, etc_owner: u32, user: &str, uid: u32) -> Result<Self, Error> {
        usable_name(user)?;
        Ok(Self { etc: etc.into(), etc_owner, budget: None, user: user.into(), uid })
    }

    /// The same files, plus the budget in `dir`, which must belong to `owner` and `group`.
    pub fn with_budget(self, dir: impl Into<PathBuf>, owner: u32, group: u32) -> Self {
        Self { budget: Some(SharedDir { path: dir.into(), owner, group }), ..self }
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn etc_owner(&self) -> u32 {
        self.etc_owner
    }

    pub fn config(&self) -> PathBuf {
        self.etc.join("config")
    }

    pub fn user_file(&self) -> PathBuf {
        self.etc.join("users").join(&self.user)
    }

    pub fn lock_file(&self) -> Option<PathBuf> {
        Some(self.budget.as_ref()?.path.join(format!("{}.lock", self.uid)))
    }

    pub fn budget_file(&self) -> Option<PathBuf> {
        Some(self.budget.as_ref()?.path.join(format!("{}.budget", self.uid)))
    }

    // --- the owner's side: settings and hash

    /// The settings in `path`, if the owner owns it, nobody else can change it, and `readers` can
    /// read it (see [`read_trusted`]).
    fn read_pairs(&self, path: &Path, readers: Readers) -> Result<kv::Pairs, Error> {
        let text = read_trusted(path, &[self.etc_owner], readers)?.unwrap_or_default();
        kv::parse(&text, &path.display().to_string())
    }

    /// The pinchecker's group, the only one that may read the user's file. It comes with the
    /// budget directory, which has the same group.
    fn group(&self) -> Result<u32, Error> {
        self.budget.as_ref().map(|budget| budget.group).ok_or_else(|| Error::System("no budget directory given".into()))
    }

    /// The pairs in the user's own file.
    fn user_pairs(&self) -> Result<kv::Pairs, Error> {
        self.read_pairs(&self.user_file(), Readers::Group(self.group()?))
    }

    /// The user's own file alone, its hash on top of the defaults, by the rules [`Store::settings`]
    /// applies to it: `properpin doctor`, which tells a problem with this file from one with the
    /// config.
    pub fn user_settings(&self) -> Result<Settings, Error> {
        let mut settings = Settings::default();
        settings.apply(&self.user_pairs()?, &self.user_file().display().to_string(), true)?;
        Ok(settings)
    }

    /// Atomically write a new PIN's hash as the user's whole file: owned by the owner, readable by
    /// the pinchecker's group, mode 0640. Whatever the file held before is gone.
    pub fn save_pin(&self, hash: &str) -> Result<(), Error> {
        let path = self.user_file();
        let group = self.group()?;
        let pairs = [(HASH_SETTING.to_owned(), hash.to_owned())];
        let dir = path.parent().expect("the user file is inside users/");
        // Made as install makes it, should it be missing: the owner's and the group's, mode 0750.
        if fs::symlink_metadata(dir).is_err_and(|error| error.kind() == ErrorKind::NotFound) {
            let create = || -> std::io::Result<()> {
                fs::DirBuilder::new().recursive(true).mode(0o755).create(dir.parent().expect("users/ is inside etc"))?;
                fs::DirBuilder::new().mode(0o750).create(dir)?;
                std::os::unix::fs::chown(dir, Some(self.etc_owner), Some(group))?;
                fs::set_permissions(dir, Permissions::from_mode(0o750))
            };
            create().map_err(|error| system(dir.display(), error))?;
        }
        let write = || -> std::io::Result<()> {
            let mut file = tempfile::Builder::new().prefix(&format!(".{}.", self.user)).tempfile_in(dir)?;
            fchown(file.as_file(), Some(self.etc_owner), Some(group))?;
            file.as_file().set_permissions(Permissions::from_mode(0o640))?;
            file.write_all(kv::format(&pairs).as_bytes())?;
            file.as_file().sync_all()?;
            file.persist(&path)?;
            Ok(())
        };
        write().map_err(|error| system(path.display(), error))
    }

    /// Delete the user's file, whatever stands there, and what a killed
    /// `set` left beside it. `false` when there was no file.
    pub fn remove_pin(&self) -> Result<bool, Error> {
        remove_user_file(&self.etc, &self.user)
    }

    /// Give a new PIN its budget and lock file, as root: `properpin set`. The lock is taken first,
    /// so an attempt still running finishes before the budget is replaced. A lock file that isn't
    /// the user's own goes, so does whatever stands in its place, and a new one is created for the
    /// user: root can delete anything here, so whatever got there, a fresh `set` repairs it.
    pub fn start_budget(&self, budget: &Budget) -> Result<(), Error> {
        let dir = self.trusted_budget_dir()?;
        let group = self.budget.as_ref().expect("checked by trusted_budget_dir").group;
        let path = dir.join(format!("{}.lock", self.uid));
        let file = match self.open_lock(&path) {
            Ok(file) => file,
            Err(_) => {
                let create = || -> std::io::Result<File> {
                    match fs::remove_file(&path) {
                        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
                        _ => {}
                    }
                    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(O_NOFOLLOW).open(&path)?;
                    fchown(&file, Some(self.uid), Some(group))?;
                    Ok(file)
                };
                create().map_err(|error| system(path.display(), error))?
            }
        };
        let _lock = flock(file, &path)?;
        self.save_budget(budget)
    }

    /// Delete the budget and the lock file: `remove`, which leaves none behind. Root can delete
    /// both whoever owns them. Under the lock, when there is one of the user's to take: an attempt
    /// under way finishes first, and one waiting behind it then finds its lock file gone.
    pub fn remove_budget(&self) -> Result<bool, Error> {
        let dir = self.trusted_budget_dir()?;
        let path = dir.join(format!("{}.lock", self.uid));
        let _lock = match self.open_lock(&path) {
            Ok(file) => Some(flock(file, &path)?),
            Err(_) => None,
        };
        let remove = |path: PathBuf| match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(system(path.display(), error)),
        };
        self.remove_leftovers(dir);
        remove(path)?;
        remove(dir.join(format!("{}.budget", self.uid)))
    }

    /// Every check an attempt makes on the lock file and the budget, without taking the lock or
    /// changing anything: `properpin doctor` and `status`.
    pub fn check_budget(&self) -> Result<(), Error> {
        let dir = self.trusted_budget_dir()?;
        self.open_lock(&dir.join(format!("{}.lock", self.uid)))?;
        self.load_budget().map(drop)
    }

    // --- the pinchecker's side: the budget

    fn trusted_budget_dir(&self) -> Result<&Path, Error> {
        let budget = self.budget.as_ref().ok_or_else(|| Error::System("no budget directory given".into()))?;
        trusted_dir(budget, "budget directory")
    }

    /// How the user's temporary budget files start: `.<uid>.`, followed by a random name.
    fn leftover_prefix(&self) -> String {
        format!(".{}.", self.uid)
    }

    /// Delete the temporary files that writes of the user's budget left when they were killed.
    /// Called under the lock, when no other write of the user's is under way, so every such file
    /// is a leftover. Best effort: what can't be deleted stays, such as a file someone else
    /// planted under the user's prefix, which the sticky bit keeps the user's own runs from
    /// deleting and root's next write deletes. The names are random, unlike the lock file's and
    /// the budget's, so nobody can plant the one the next write takes.
    fn remove_leftovers(&self, dir: &Path) {
        let prefix = self.leftover_prefix();
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            if entry.file_name().to_str().is_some_and(|name| name.starts_with(&prefix)) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// The user's lock file at `path`, which must exist, be a regular file and be the user's own,
    /// readable and writable by them.
    fn open_lock(&self, path: &Path) -> Result<File, Error> {
        // Read and write: opening a FIFO planted in its place for reading alone would block.
        let file =
            OpenOptions::new().read(true).write(true).custom_flags(O_NOFOLLOW).open(path).map_err(|error| system(path.display(), error))?;
        let info = file.metadata().map_err(|error| system(path.display(), error))?;
        let refuse = |why: String| Err(Error::System(format!("{}: {why}", path.display())));
        if !info.is_file() {
            return refuse("not a regular file".into());
        }
        if info.uid() != self.uid {
            return refuse(format!("owned by uid {}, not {}", info.uid(), self.uid));
        }
        // Only root, which opens anything, gets this far with a file its owner can't open.
        if info.mode() & 0o600 != 0o600 {
            return refuse("not readable and writable by its owner".into());
        }
        Ok(file)
    }
}

/// Refuse a shared directory that isn't exactly as installed: a directory, not a symlink, owned by
/// the owner and the pinchecker's group, mode 1770. Without the group's write bit the pinchecker can't
/// keep its files; without the sticky bit one user's run could delete or replace another's files;
/// any bit for others would let users in.
fn trusted_dir<'a>(dir: &'a SharedDir, what: &str) -> Result<&'a Path, Error> {
    let info = fs::symlink_metadata(&dir.path).map_err(|error| system(dir.path.display(), error))?;
    let refuse = |why: String| Err(Error::System(format!("{what} {}: {why}", dir.path.display())));
    if !info.is_dir() {
        return refuse("not a directory".into());
    }
    if info.uid() != dir.owner {
        return refuse(format!("owned by uid {}, not {}", info.uid(), dir.owner));
    }
    if info.gid() != dir.group {
        return refuse(format!("group {}, not {}", info.gid(), dir.group));
    }
    if info.mode() & 0o7777 != 0o1770 {
        return refuse(format!("mode {:04o}, not 1770", info.mode() & 0o7777));
    }
    Ok(&dir.path)
}

impl Store for UserFiles {
    type Lock = Flock<File>;

    fn settings(&self) -> Result<Settings, Error> {
        let mut settings = Settings::default();
        let config = self.config();
        settings.apply(&self.read_pairs(&config, Readers::Everyone)?, &config.display().to_string(), false)?;
        settings.apply(&self.user_pairs()?, &self.user_file().display().to_string(), true)?;
        Ok(settings)
    }

    /// Every write of the budget happens under this lock. The lock file must exist, created by
    /// `properpin set`, and be the user's own: one that is missing or isn't refuses the PIN, and a
    /// fresh `set` repairs it. Opened without `O_CREAT`, which `fs.protected_regular` would refuse
    /// root in this sticky, group-writable directory, even for a file that exists.
    fn lock(&self) -> Result<Flock<File>, Error> {
        let path = self.trusted_budget_dir()?.join(format!("{}.lock", self.uid));
        let file = self.open_lock(&path)?;
        flock(file, &path)
    }

    /// The budget must be the user's own and private; one that isn't is an error, never an empty
    /// budget.
    fn load_budget(&self) -> Result<Budget, Error> {
        let path = self.trusted_budget_dir()?.join(format!("{}.budget", self.uid));
        let refuse = |why: &str| Err(Error::System(format!("{}: {why}", path.display())));
        let (info, text) = match read_regular_file(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return refuse("missing"),
            result => result.map_err(|error| system(path.display(), error))?,
        };
        if info.uid() != self.uid {
            return refuse(&format!("owned by uid {}, not {}", info.uid(), self.uid));
        }
        if info.mode() & 0o077 != 0 {
            return refuse("open to its group or others");
        }
        // Only root, which reads anything, gets this far with a file its owner can't read.
        if info.mode() & 0o400 == 0 {
            return refuse("not readable by its owner");
        }
        Budget::parse(&text).map_or_else(|| refuse("not a valid budget"), Ok)
    }

    /// Written for the user and the pinchecker's group whoever writes it: the pinchecker, as the user, or
    /// `properpin set` and `enable`, as root, always under the lock. Synced, file and directory, since
    /// it must survive a power cut. A write killed halfway leaves its temporary file behind, so the
    /// next one clears any of the user's first (see [`UserFiles::remove_leftovers`]).
    fn save_budget(&self, budget: &Budget) -> Result<(), Error> {
        let dir = self.trusted_budget_dir()?;
        let group = self.budget.as_ref().expect("checked by trusted_budget_dir").group;
        let path = dir.join(format!("{}.budget", self.uid));
        self.remove_leftovers(dir);
        let write = || -> std::io::Result<()> {
            let mut file = tempfile::Builder::new().prefix(&self.leftover_prefix()).tempfile_in(dir)?;
            fchown(file.as_file(), Some(self.uid), Some(group))?;
            file.as_file().set_permissions(Permissions::from_mode(0o600))?;
            file.write_all(budget.format().as_bytes())?;
            file.as_file().sync_all()?;
            file.persist(&path)?;
            File::open(dir)?.sync_all()
        };
        write().map_err(|error| system(path.display(), error))
    }
}

/// An exclusive lock on `file`, the lock file at `path`, waiting at most [`LOCK_TIMEOUT`] for
/// whoever holds it. Refused when `path` no longer names `file` by then: `remove` deleted it while
/// this waited, perhaps followed by a `set` that created a new one, and a lock on the old file
/// would keep nobody out.
fn flock(mut file: File, path: &Path) -> Result<Flock<File>, Error> {
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => {
                let held = lock.metadata().map_err(|error| system(path.display(), error))?;
                return match fs::symlink_metadata(path) {
                    Ok(now) if (now.dev(), now.ino()) == (held.dev(), held.ino()) => Ok(lock),
                    _ => Err(Error::System(format!("{}: deleted or replaced while waiting for it", path.display()))),
                };
            }
            Err((_, errno)) if Instant::now() >= deadline => return Err(system(path.display(), errno)),
            Err((returned, _)) => file = returned,
        }
        sleep(Duration::from_millis(10));
    }
}

/// The global settings alone, from the config at `path`, for the PAM module: it runs as the user,
/// who can't read their own file. Trusted when owned by root, or by `uid`, the user the module
/// runs as: the one setting the module uses changes only how long that user's own correct PIN
/// waits, and the tests' sandboxes belong to the user running them. Defaults when there is no
/// config.
pub fn global_settings(path: &Path, uid: u32) -> Result<Settings, Error> {
    config_settings(path, &[0, uid])
}

/// The config at `path` on top of the defaults, trusted when owned by one of `owners`.
fn config_settings(path: &Path, owners: &[u32]) -> Result<Settings, Error> {
    let text = read_trusted(path, owners, Readers::Everyone)?.unwrap_or_default();
    let source = path.display().to_string();
    let mut settings = Settings::default();
    settings.apply(&kv::parse(&text, &source)?, &source, false)?;
    Ok(settings)
}

/// Every user's files at once, for root: what `properpin doctor` looks at, and what `remove --all`
/// and `restore-defaults` delete. [`AllUsers::user`] gives one user's [`UserFiles`].
#[derive(Debug, Clone)]
pub struct AllUsers {
    etc: PathBuf,
    etc_owner: u32,
    budget: SharedDir,
}

impl AllUsers {
    /// The files under `etc`, which must belong to `etc_owner`, and the budgets in `budget_dir`,
    /// which must belong to `budget_owner` and `group`, the pinchecker's.
    pub fn new(etc: impl Into<PathBuf>, etc_owner: u32, budget_dir: impl Into<PathBuf>, budget_owner: u32, group: u32) -> Self {
        Self { etc: etc.into(), etc_owner, budget: SharedDir { path: budget_dir.into(), owner: budget_owner, group } }
    }

    /// The files of the user named `user`, whose uid is `uid`.
    pub fn user(&self, user: &str, uid: u32) -> Result<UserFiles, Error> {
        let files = UserFiles::new(&self.etc, self.etc_owner, user, uid)?;
        Ok(files.with_budget(&self.budget.path, self.budget.owner, self.budget.group))
    }

    pub fn config(&self) -> PathBuf {
        self.etc.join("config")
    }

    pub fn users_dir(&self) -> PathBuf {
        self.etc.join("users")
    }

    /// The config alone, on top of the defaults, by the rules the pinchecker applies to it.
    pub fn config_settings(&self) -> Result<Settings, Error> {
        config_settings(&self.config(), &[self.etc_owner])
    }

    /// The budget directory, by the rules every attempt applies to it.
    pub fn check_budget_dir(&self) -> Result<(), Error> {
        trusted_dir(&self.budget, "budget directory").map(drop)
    }

    /// `<etc>/users` as install makes it: a directory owned by the owner and the pinchecker's group,
    /// mode 0750. The pinchecker never checks it, but can't reach a user's file through a directory
    /// its group can't enter, which root, reading everything, would never notice.
    pub fn check_users_dir(&self) -> Result<(), Error> {
        let path = self.users_dir();
        let info = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            result => result.map_err(|error| system(path.display(), error))?,
        };
        let refuse = |why: String| Err(Error::System(format!("{}: {why}", path.display())));
        if !info.is_dir() {
            return refuse("not a directory".into());
        }
        if info.uid() != self.etc_owner {
            return refuse(format!("owned by uid {}, not {}", info.uid(), self.etc_owner));
        }
        if info.gid() != self.budget.group {
            return refuse(format!("group {}, not {}", info.gid(), self.budget.group));
        }
        if info.mode() & 0o7777 != 0o750 {
            return refuse(format!("mode {:04o}, not 0750", info.mode() & 0o7777));
        }
        Ok(())
    }

    /// The names of the users with a file in `<etc>/users`, sorted, without the temporary files
    /// a killed `set` left. None when there is no such directory.
    pub fn names(&self) -> Result<Vec<String>, Error> {
        let dir = self.users_dir();
        let entries = match fs::read_dir(&dir) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            result => result.map_err(|error| system(dir.display(), error))?,
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| system(dir.display(), error))?;
            if let Some(name) = entry.file_name().to_str().filter(|name| !name.starts_with('.')) {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Delete the file of the user named `user` by name alone: `remove` for an account that no
    /// longer exists, which has no uid to find a budget by. `false` when there was none.
    pub fn remove_user_file(&self, user: &str) -> Result<bool, Error> {
        remove_user_file(&self.etc, user)
    }

    /// Delete the config, whatever stands there: `restore-defaults`. `false` when there was none.
    pub fn remove_config(&self) -> Result<bool, Error> {
        remove_entry(&self.config())
    }

    /// Delete everything in `<etc>/users` and in the budget directory, whatever it is: `remove
    /// --all`, once each user's PIN went the way `remove` takes it. Nothing reads what is left:
    /// an attempt for a user without a file stops before the budget. Each directory must be a
    /// directory, not a symlink, and the owner's, so nothing outside them is ever deleted.
    pub fn remove_everything_left(&self) -> Result<(), Error> {
        for (dir, owner) in [(self.users_dir(), self.etc_owner), (self.budget.path.clone(), self.budget.owner)] {
            let info = match fs::symlink_metadata(&dir) {
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                result => result.map_err(|error| system(dir.display(), error))?,
            };
            if !info.is_dir() || info.uid() != owner {
                return Err(Error::System(format!("{}: not a directory of uid {owner}, so nothing in it was deleted", dir.display())));
            }
            for entry in fs::read_dir(&dir).map_err(|error| system(dir.display(), error))? {
                remove_entry(&entry.map_err(|error| system(dir.display(), error))?.path())?;
            }
        }
        Ok(())
    }
}

/// Delete `<etc>/users/<user>`, whatever stands there, and the temporary files a killed `set` of
/// the user's left: `.<user>.` followed by tempfile's six random letters and digits. `false` when
/// there was no file.
fn remove_user_file(etc: &Path, user: &str) -> Result<bool, Error> {
    usable_name(user)?;
    let dir = etc.join("users");
    let removed = remove_entry(&dir.join(user))?;
    let prefix = format!(".{user}.");
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let leftover = name.to_str().and_then(|name| name.strip_prefix(&prefix));
            if leftover.is_some_and(|rest| rest.len() == 6 && rest.bytes().all(|byte| byte.is_ascii_alphanumeric())) {
                remove_entry(&entry.path())?;
            }
        }
    }
    Ok(removed)
}

/// Delete `path`, whatever it is: a file, a symlink (never what it points to) or a directory with
/// everything in it. `false` when there was nothing.
fn remove_entry(path: &Path) -> Result<bool, Error> {
    let removed = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => Err(error),
        Ok(info) if info.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
    };
    removed.map(|()| true).map_err(|error| system(path.display(), error))
}

/// A user name that can only ever name a file directly inside `users/`.
fn usable_name(user: &str) -> Result<(), Error> {
    if user.is_empty() || user.contains('/') || user == "." || user == ".." {
        return Err(Error::System(format!("{user:?} is not a usable user name")));
    }
    Ok(())
}

/// Who reads a trusted file, besides root.
#[derive(Debug, Clone, Copy)]
enum Readers {
    /// Everyone: the global config, which the PAM module reads as the user.
    Everyone,
    /// The pinchecker's group alone: a user's own file, which holds the hash.
    Group(u32),
}

/// The text of `path`, provided it can be trusted: a regular file, not a symlink, owned by one of
/// `owners`, that nobody else can change, and that `readers` can read: everyone, or the group
/// alone, which must then be the pinchecker's. `None` when there is no such file.
fn read_trusted(path: &Path, owners: &[u32], readers: Readers) -> Result<Option<String>, Error> {
    let (info, text) = match read_regular_file(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        result => result.map_err(|error| system(path.display(), error))?,
    };
    let refuse = |why: String| Err(Error::System(format!("{}: {why}", path.display())));
    if !owners.contains(&info.uid()) {
        let owners: Vec<String> = owners.iter().map(u32::to_string).collect();
        return refuse(format!("owned by uid {}, not {}", info.uid(), owners.join(" or ")));
    }
    if info.mode() & 0o022 != 0 {
        return refuse("writable by its group or by others".into());
    }
    // Only root, which reads anything, gets past the open with a file its readers can't read.
    match readers {
        Readers::Everyone if info.mode() & 0o004 == 0 => refuse("not readable by others, and the PAM module reads it as the user".into()),
        Readers::Group(_) if info.mode() & 0o004 != 0 => refuse("readable by others".into()),
        Readers::Group(group) if info.gid() != group => refuse(format!("group {}, not {group}", info.gid())),
        Readers::Group(_) if info.mode() & 0o040 == 0 => refuse("not readable by its group".into()),
        _ => Ok(Some(text)),
    }
}

/// The metadata and text of `path`, which must be a regular file and not a symlink. Both come from
/// one open file, so the file checked is the file read.
fn read_regular_file(path: &Path) -> std::io::Result<(Metadata, String)> {
    let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path)?;
    let info = file.metadata()?;
    if !info.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut text = String::new();
    file.take(MAX_FILE_BYTES as u64 + 1).read_to_string(&mut text)?;
    if text.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::other(format!("longer than {MAX_FILE_BYTES} bytes")));
    }
    Ok((info, text))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::{current_egid, current_uid};

    /// A scratch `etc` and `var` owned by whoever runs the tests.
    struct Scratch {
        _dir: tempfile::TempDir,
        files: UserFiles,
    }

    fn scratch() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        let uid = current_uid();
        fs::create_dir(dir.path().join("var")).unwrap();
        // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
        fs::set_permissions(dir.path().join("var"), Permissions::from_mode(0o1770)).unwrap();
        let files =
            UserFiles::new(dir.path().join("etc"), uid, "tester", uid).unwrap().with_budget(dir.path().join("var"), uid, current_egid());
        Scratch { _dir: dir, files }
    }

    fn write(path: &Path, text: &str, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn settings_come_from_the_config_and_the_hash_from_the_user_file() {
        let Scratch { files, .. } = &scratch();
        write(&files.config(), "max_failures = 5\nhash_cost = 6\n", 0o644);
        write(&files.user_file(), "hash = $y$j9T$abc$def\n", 0o640);
        let settings = files.settings().unwrap();
        assert_eq!((settings.max_failures, settings.hash_cost, settings.pin_hash.as_str()), (5, 6, "$y$j9T$abc$def"));
        write(&files.user_file(), "hash = $y$j9T$abc$def\nmax_failures = 2\n", 0o640);
        assert!(matches!(files.settings(), Err(Error::OnlyTheHash { .. })));
        assert!(matches!(files.user_settings(), Err(Error::OnlyTheHash { .. })), "doctor's rules are the pinchecker's");
    }

    #[test]
    fn the_pam_module_reads_the_global_config_alone() {
        let Scratch { files, .. } = &scratch();
        let uid = current_uid();
        assert_eq!(global_settings(&files.config(), uid).unwrap(), Settings::default(), "no config, the defaults");
        write(&files.config(), "min_milliseconds_before_pin_unlock = 300\nmax_failures = 5\n", 0o644);
        write(&files.user_file(), "max_failures = 2\n", 0o640);
        let settings = global_settings(&files.config(), uid).unwrap();
        assert_eq!((settings.min_milliseconds_before_pin_unlock, settings.max_failures), (300, 5));
        let error = global_settings(&files.config(), uid + 1).unwrap_err().to_string();
        assert!(error.contains(&format!("owned by uid {uid}, not 0 or {}", uid + 1)), "{error}");
        write(&files.config(), "min_milliseconds_before_pin_unlock = 300\n", 0o664);
        assert!(global_settings(&files.config(), uid).unwrap_err().to_string().contains("writable by its group"));
        write(&files.config(), "hash = $y$j9T$abc$def\n", 0o644);
        assert!(matches!(global_settings(&files.config(), uid), Err(Error::OutsideUserFile { .. })));
    }

    /// The test owns its files, as root would: it can read what the pinchecker couldn't, so the
    /// readers' rules are what refuses those.
    #[test]
    fn untrusted_files_are_refused() {
        let Scratch { files, .. } = &scratch();
        for (mode, why) in [(0o660, "writable by its group"), (0o644, "readable by others"), (0o600, "not readable by its group")] {
            write(&files.user_file(), "hash = $y$x\n", mode);
            let error = files.settings().unwrap_err().to_string();
            assert!(error.contains(why), "{error}");
            assert_eq!(files.user_settings().unwrap_err().to_string(), error, "doctor's rules are the pinchecker's");
        }
        let budget = files.budget.clone().unwrap();
        let other_owner = UserFiles::new(files.etc.clone(), files.etc_owner + 1, "tester", files.uid).unwrap().with_budget(
            &budget.path,
            budget.owner,
            budget.group,
        );
        write(&files.user_file(), "hash = $y$x\n", 0o640);
        assert!(other_owner.settings().unwrap_err().to_string().contains("owned by uid"));
        let other_group = files.clone().with_budget(&budget.path, budget.owner, budget.group + 1);
        let error = other_group.settings().unwrap_err().to_string();
        assert!(error.contains(&format!("group {}, not {}", budget.group, budget.group + 1)), "{error}");
        assert!(files.settings().is_ok(), "and the right group reads it");

        write(&files.config(), "max_failures = 2\n", 0o640);
        let error = files.settings().unwrap_err().to_string();
        assert!(error.contains("not readable by others, and the PAM module reads it as the user"), "{error}");
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let Scratch { files, .. } = &scratch();
        let real = files.etc.join("elsewhere");
        write(&real, "max_failures = 10\n", 0o644);
        symlink(&real, files.config()).unwrap();
        assert!(files.settings().is_err());
    }

    /// `set` makes a missing `users/` as install would, so doctor finds nothing wrong with it.
    #[test]
    fn saving_a_hash_makes_the_users_directory_as_install_does() {
        let Scratch { files, .. } = &scratch();
        files.save_pin("$y$new").unwrap();
        let info = fs::metadata(files.etc.join("users")).unwrap();
        assert_eq!((info.mode() & 0o7777, info.gid()), (0o750, current_egid()));
        let all = AllUsers::new(&files.etc, files.etc_owner, &files.budget.as_ref().unwrap().path, files.etc_owner, current_egid());
        all.check_users_dir().unwrap();
        fs::set_permissions(files.etc.join("users"), Permissions::from_mode(0o755)).unwrap();
        assert!(all.check_users_dir().unwrap_err().to_string().contains("mode 0755, not 0750"));
    }

    #[test]
    fn saving_a_hash_replaces_the_whole_file_and_sets_the_mode() {
        let Scratch { files, .. } = &scratch();
        // A file from a version with per-user settings, which the pinchecker now refuses.
        write(&files.user_file(), "hash = $y$old\nmax_failures = 2\n", 0o640);
        files.save_pin("$y$new").unwrap();
        assert_eq!(fs::read_to_string(files.user_file()).unwrap(), "hash = $y$new\n");
        assert_eq!(fs::metadata(files.user_file()).unwrap().mode() & 0o777, 0o640);
        assert!(files.remove_pin().unwrap());
        assert!(!files.remove_pin().unwrap());
    }

    #[test]
    fn a_budget_dir_with_any_other_mode_is_refused() {
        let Scratch { files, .. } = &scratch();
        let dir = files.budget_file().unwrap().parent().unwrap().to_path_buf();
        for mode in [0o700, 0o770, 0o1777, 0o1775, 0o3770] {
            fs::set_permissions(&dir, Permissions::from_mode(mode)).unwrap();
            let error = files.lock().unwrap_err().to_string();
            assert!(error.contains(&format!("mode {mode:04o}, not 1770")), "{error}");
            assert!(files.save_budget(&Budget::default()).is_err());
        }
        fs::set_permissions(&dir, Permissions::from_mode(0o1770)).unwrap();
        files.start_budget(&Budget::default()).unwrap();
        assert!(files.lock().is_ok());
    }

    #[test]
    fn a_budget_dir_with_another_owner_or_group_is_refused() {
        let Scratch { files, .. } = &scratch();
        let budget = files.budget.clone().unwrap();
        let theirs = files.clone().with_budget(&budget.path, budget.owner + 1, budget.group);
        assert!(theirs.lock().unwrap_err().to_string().contains("owned by uid"));
        let theirs = files.clone().with_budget(&budget.path, budget.owner, budget.group + 1);
        assert!(theirs.lock().unwrap_err().to_string().contains(&format!("group {}, not {}", budget.group, budget.group + 1)));
    }

    #[test]
    fn a_symlinked_budget_dir_is_refused() {
        let Scratch { files, _dir } = &scratch();
        let budget = files.budget.clone().unwrap();
        let link = _dir.path().join("link");
        symlink(&budget.path, &link).unwrap();
        let linked = files.clone().with_budget(link, budget.owner, budget.group);
        assert!(linked.lock().unwrap_err().to_string().contains("not a directory"));
    }

    /// The pinchecker never creates the lock file, so a missing one is refused. A test can't make
    /// files owned by someone else, so it plays the other side: the files are built for another
    /// uid, and the file the test creates stands in for a planted one.
    #[test]
    fn a_missing_or_planted_lock_file_is_refused() {
        let Scratch { files, .. } = &scratch();
        let budget = files.budget.clone().unwrap();
        let victim = UserFiles::new(files.etc.clone(), files.etc_owner, "victim", files.uid + 1).unwrap().with_budget(
            &budget.path,
            budget.owner,
            budget.group,
        );
        let error = victim.lock().unwrap_err().to_string();
        assert!(error.contains("No such file"), "{error}");
        assert!(!victim.lock_file().unwrap().exists(), "and nothing was created");
        write(&victim.lock_file().unwrap(), "", 0o600);
        let error = victim.lock().unwrap_err().to_string();
        assert!(error.contains(&format!("owned by uid {}, not {}", files.uid, files.uid + 1)), "{error}");
    }

    /// Whatever stands where the lock file should be, set replaces it with a lock file of the user's.
    #[test]
    fn set_replaces_anything_in_place_of_the_lock_file() {
        let Scratch { files, _dir } = &scratch();
        let lock = files.lock_file().unwrap();
        symlink(_dir.path().join("elsewhere"), &lock).unwrap();
        assert!(files.lock().is_err());
        files.start_budget(&Budget::default()).unwrap();
        assert!(fs::symlink_metadata(&lock).unwrap().is_file());
        assert_eq!(fs::metadata(&lock).unwrap().mode() & 0o7777, 0o600);
        assert!(files.lock().is_ok());
    }

    #[test]
    fn without_a_budget_dir_there_is_no_lock_and_no_budget() {
        let Scratch { files, .. } = &scratch();
        let etc_only = UserFiles::new(files.etc.clone(), files.etc_owner, "tester", files.uid).unwrap();
        assert!(etc_only.lock().is_err());
        assert!(etc_only.load_budget().is_err());
    }

    #[test]
    fn the_budget_starts_at_set_and_round_trips() {
        let Scratch { files, .. } = &scratch();
        assert!(files.load_budget().unwrap_err().to_string().ends_with("budget: missing"));
        files.start_budget(&Budget::default()).unwrap();
        assert_eq!(files.load_budget().unwrap(), Budget::default());
        let budget = Budget { consecutive: 2, pending: vec![1], suspicious: vec![2], total: 3, disabled: None, set: 4, since: 5 };
        files.save_budget(&budget).unwrap();
        assert_eq!(files.load_budget().unwrap(), budget);
        assert_eq!(fs::metadata(files.budget_file().unwrap()).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(files.lock_file().unwrap()).unwrap().mode() & 0o7777, 0o600);
        assert!(files.remove_budget().unwrap());
        assert!(!files.lock_file().unwrap().exists(), "the lock file goes with the budget");
        assert!(!files.remove_budget().unwrap());
        assert!(files.load_budget().is_err());
    }

    #[test]
    fn a_budget_that_cannot_be_trusted_is_an_error_not_an_empty_budget() {
        let Scratch { files, .. } = &scratch();
        let path = files.budget_file().unwrap();
        write(&path, "garbage\n", 0o600);
        assert!(files.load_budget().unwrap_err().to_string().contains("not a valid budget"));
        write(&path, &Budget::default().format(), 0o640);
        assert!(files.load_budget().unwrap_err().to_string().contains("open to its group or others"));
        // Planted in another user's name: the test's own file stands in for the planted one.
        write(&path, &Budget::default().format(), 0o600);
        let budget = files.budget.clone().unwrap();
        let victim = UserFiles::new(files.etc.clone(), files.etc_owner, "victim", files.uid + 1).unwrap().with_budget(
            &budget.path,
            budget.owner,
            budget.group,
        );
        fs::rename(&path, victim.budget_file().unwrap()).unwrap();
        assert!(victim.load_budget().unwrap_err().to_string().contains(&format!("owned by uid {}, not {}", files.uid, files.uid + 1)));
    }

    #[test]
    fn a_budget_past_the_size_limit_is_an_error_not_a_shorter_budget() {
        let Scratch { files, .. } = &scratch();
        let path = files.budget_file().unwrap();
        let budget = Budget::default().format();
        // Padded with a comment to exactly MAX_FILE_BYTES it is read; one byte more, and it is refused.
        let padded = |length: usize| format!("{budget}#{}\n", "x".repeat(length - budget.len() - 2));
        write(&path, &padded(MAX_FILE_BYTES), 0o600);
        assert_eq!(files.load_budget().unwrap(), Budget::default());
        write(&path, &padded(MAX_FILE_BYTES + 1), 0o600);
        assert!(files.load_budget().unwrap_err().to_string().contains(&format!("longer than {MAX_FILE_BYTES} bytes")));
    }

    #[test]
    fn every_use_of_the_budget_directory_checks_it() {
        let Scratch { files, .. } = &scratch();
        let dir = files.budget.clone().unwrap().path;
        fs::set_permissions(&dir, Permissions::from_mode(0o777)).unwrap();
        assert!(files.load_budget().unwrap_err().to_string().contains("budget directory"));
        assert!(files.save_budget(&Budget::default()).is_err());
        assert!(files.remove_budget().is_err());
    }

    /// A write killed halfway leaves its temporary file; the next write, or `remove`, clears it,
    /// and only the user's own.
    #[test]
    fn a_killed_writes_leftover_goes_at_the_next_write() {
        let Scratch { files, .. } = &scratch();
        files.start_budget(&Budget::default()).unwrap();
        let dir = files.budget_file().unwrap().parent().unwrap().to_path_buf();
        let (mine, theirs) = (dir.join(format!(".{}.k1lled", files.uid)), dir.join(format!(".{}0.k1lled", files.uid)));
        for path in [&mine, &theirs] {
            write(path, "consecutive = 0\n", 0o600);
        }
        files.save_budget(&Budget::default()).unwrap();
        assert!(!mine.exists() && theirs.exists());
        write(&mine, "", 0o600);
        files.remove_budget().unwrap();
        assert!(!mine.exists() && theirs.exists());
        let left: Vec<_> = fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(left, [theirs.file_name().unwrap()], "remove leaves nothing of the user's");
    }

    /// `remove` waits for an attempt that holds the lock, and an attempt that was waiting on a
    /// lock file deleted meanwhile, and perhaps created anew by `set`, is refused.
    #[test]
    fn remove_waits_for_the_lock_and_a_replaced_lock_file_is_refused() {
        let Scratch { files, .. } = &scratch();
        files.start_budget(&Budget::default()).unwrap();
        let held = files.lock().unwrap();
        assert!(files.remove_budget().is_err());
        assert!(files.budget_file().unwrap().exists() && files.lock_file().unwrap().exists(), "nothing removed");
        drop(held);

        let path = files.lock_file().unwrap();
        let waiting = files.open_lock(&path).unwrap();
        files.remove_budget().unwrap();
        files.start_budget(&Budget::default()).unwrap();
        let error = flock(waiting, &path).unwrap_err().to_string();
        assert!(error.contains("deleted or replaced while waiting"), "{error}");
        assert!(files.lock().is_ok(), "the new lock file works");
    }

    #[test]
    fn a_held_lock_times_out_instead_of_hanging() {
        let Scratch { files, .. } = &scratch();
        files.start_budget(&Budget::default()).unwrap();
        let _held = files.lock().unwrap();
        let started = Instant::now();
        assert!(files.lock().is_err());
        assert!(started.elapsed() < LOCK_TIMEOUT * 2);
        assert!(files.start_budget(&Budget::default()).is_err(), "set waits for an attempt still running, too");
    }

    fn all_users(files: &UserFiles) -> AllUsers {
        let budget = files.budget.clone().unwrap();
        AllUsers::new(&files.etc, files.etc_owner, &budget.path, budget.owner, budget.group)
    }

    /// The temporary files a killed `set` left go with the user's file, and nobody else's do.
    #[test]
    fn removing_a_user_file_takes_whatever_stands_there() {
        let Scratch { files, _dir } = &scratch();
        let all = all_users(files);
        let users = files.etc.join("users");
        write(&users.join("tester"), "hash = $y$x\n", 0o644);
        write(&users.join(".tester.Ab3dE9"), "", 0o640);
        write(&users.join(".tester.x.Ab3dE9"), "", 0o640);
        write(&users.join("other"), "", 0o640);
        assert_eq!(all.names().unwrap(), ["other", "tester"], "without the leftovers");
        assert!(files.remove_pin().unwrap());
        let mut left: Vec<_> = fs::read_dir(&users).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        left.sort();
        assert_eq!(left, [".tester.x.Ab3dE9", "other"]);
        assert!(!files.remove_pin().unwrap());

        // A directory or a symlink goes too, and never what the symlink points to.
        fs::create_dir_all(users.join("gone/deeper")).unwrap();
        assert!(all.remove_user_file("gone").unwrap());
        let elsewhere = _dir.path().join("elsewhere");
        write(&elsewhere, "keep me", 0o644);
        symlink(&elsewhere, users.join("linked")).unwrap();
        assert!(all.remove_user_file("linked").unwrap());
        assert!(elsewhere.exists());
        assert!(all.remove_user_file("../etc").is_err());
    }

    #[test]
    fn removing_everything_left_empties_both_directories_and_nothing_else() {
        let Scratch { files, _dir } = &scratch();
        let all = all_users(files);
        files.save_pin("$y$x").unwrap();
        files.start_budget(&Budget::default()).unwrap();
        write(&files.etc.join("users/.tester.Ab3dE9"), "", 0o640);
        write(&files.config(), "max_failures = 2\n", 0o644);
        all.remove_everything_left().unwrap();
        let budget_dir = files.budget.clone().unwrap().path;
        for dir in [files.etc.join("users"), budget_dir.clone()] {
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "{} isn't empty", dir.display());
        }
        assert!(files.config().exists(), "the config is restore-defaults' to delete");
        assert!(all.remove_config().unwrap() && !files.config().exists());
        assert!(!all.remove_config().unwrap());

        // A symlinked directory is never followed into.
        let elsewhere = _dir.path().join("elsewhere");
        write(&elsewhere.join("keep"), "", 0o644);
        fs::remove_dir(files.etc.join("users")).unwrap();
        symlink(&elsewhere, files.etc.join("users")).unwrap();
        assert!(all.remove_everything_left().unwrap_err().to_string().contains("nothing in it was deleted"));
        assert!(elsewhere.join("keep").exists());
    }
}
