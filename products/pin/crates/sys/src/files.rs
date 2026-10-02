use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::O_NOFOLLOW;
use properpin_core::{Error, HASH_KEY, MAX_FILE_BYTES, PinState, Settings, Store, kv};

use crate::system;

/// How long an attempt waits for another one to finish with the state. The lock screen must never
/// hang on properpin, so after this the attempt gives up and the password is checked instead.
const LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// One user's properpin files, and the rules for trusting each of them:
///
/// ```text
/// <etc>/config               global settings, optional            owner-only writable
/// <etc>/users/<user>         the user's settings and hash         owner:<helper group> 0640
/// <run_dir>/<uid>.state      a PinState                           the helper account's, on tmpfs
/// <run_dir>/<uid>.lock       serialises concurrent attempts       the helper account's
/// ```
///
/// The settings and the hash must belong to `etc_owner`, so nobody else can change them: root once
/// installed, the test's own uid in tests. The state lives in one directory for all users, owned by
/// `run_owner`, the account the setuid helper runs as, so a user can neither read nor reset their
/// counts. `properpin set` and `remove` need only the `etc` side; [`UserFiles::with_runtime`] adds
/// the state, which only the helper uses.
#[derive(Debug, Clone)]
pub struct UserFiles {
    etc: PathBuf,
    etc_owner: u32,
    runtime: Option<Runtime>,
    user: String,
    uid: u32,
}

#[derive(Debug, Clone)]
struct Runtime {
    dir: PathBuf,
    owner: u32,
}

impl UserFiles {
    pub fn new(etc: impl Into<PathBuf>, etc_owner: u32, user: &str, uid: u32) -> Result<Self, Error> {
        if user.is_empty() || user.contains('/') || user == "." || user == ".." {
            return Err(Error::System(format!("{user:?} is not a usable user name")));
        }
        Ok(Self { etc: etc.into(), etc_owner, runtime: None, user: user.into(), uid })
    }

    /// The same files, plus the per-boot state in `dir`, which must belong to `owner`.
    pub fn with_runtime(self, dir: impl Into<PathBuf>, owner: u32) -> Self {
        Self { runtime: Some(Runtime { dir: dir.into(), owner }), ..self }
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

    fn runtime(&self) -> Result<&Runtime, Error> {
        self.runtime.as_ref().ok_or_else(|| Error::System("no runtime directory: only the helper keeps state".into()))
    }

    pub fn state_file(&self) -> Option<PathBuf> {
        Some(self.runtime.as_ref()?.dir.join(format!("{}.state", self.uid)))
    }

    pub fn lock_file(&self) -> Option<PathBuf> {
        Some(self.runtime.as_ref()?.dir.join(format!("{}.lock", self.uid)))
    }

    // --- the owner's side: settings and hash

    /// The text of `path`, provided it can be trusted: a regular file, not a symlink, owned by the
    /// owner, that nobody else can change. `private` also refuses a file others can read.
    /// `None` when there is no such file.
    fn read_trusted(&self, path: &Path, private: bool) -> Result<Option<String>, Error> {
        let (info, text) = match read_regular_file(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            result => result.map_err(|error| system(path.display(), error))?,
        };
        let refuse = |why: String| Err(Error::System(format!("{}: {why}", path.display())));
        if info.uid() != self.etc_owner {
            return refuse(format!("owned by uid {}, not {}", info.uid(), self.etc_owner));
        }
        if info.mode() & 0o022 != 0 {
            return refuse("writable by its group or by others".into());
        }
        if private && info.mode() & 0o004 != 0 {
            return refuse("readable by others".into());
        }
        Ok(Some(text))
    }

    fn read_pairs(&self, path: &Path, private: bool) -> Result<kv::Pairs, Error> {
        let text = self.read_trusted(path, private)?.unwrap_or_default();
        kv::parse(&text, &path.display().to_string())
    }

    /// Atomically write a new hash into the user's file: owned by the owner, readable by `group`
    /// (the helper's), mode 0640. The user's other settings in the file are kept as they are.
    pub fn save_pin_hash(&self, hash: &str, group: u32) -> Result<(), Error> {
        let path = self.user_file();
        let pairs = kv::with(self.read_pairs(&path, true)?, HASH_KEY, hash);
        let dir = path.parent().expect("the user file is inside users/");
        fs::DirBuilder::new().recursive(true).mode(0o755).create(dir).map_err(|error| system(dir.display(), error))?;
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

    /// Delete the user's file, hash and settings both. `false` when there was none.
    pub fn remove_pin(&self) -> Result<bool, Error> {
        let path = self.user_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(system(path.display(), error)),
        }
    }

    // --- the helper's side: per-boot state

    /// Refuse a runtime directory that isn't the helper account's own private one.
    fn private_run_dir(&self) -> Result<&Path, Error> {
        let runtime = self.runtime()?;
        let info = fs::symlink_metadata(&runtime.dir).map_err(|error| system(runtime.dir.display(), error))?;
        if !info.is_dir() || info.uid() != runtime.owner || info.mode() & 0o077 != 0 {
            return Err(Error::System(format!("{} is not a private directory owned by uid {}", runtime.dir.display(), runtime.owner)));
        }
        Ok(&runtime.dir)
    }
}

impl Store for UserFiles {
    type Lock = Flock<File>;

    fn settings(&self) -> Result<Settings, Error> {
        let mut settings = Settings::default();
        let (config, user_file) = (self.config(), self.user_file());
        settings.apply(&self.read_pairs(&config, false)?, &config.display().to_string(), false)?;
        settings.apply(&self.read_pairs(&user_file, true)?, &user_file.display().to_string(), true)?;
        Ok(settings)
    }

    fn lock(&self) -> Result<Flock<File>, Error> {
        let path = self.private_run_dir()?.join(format!("{}.lock", self.uid));
        let open = OpenOptions::new().read(true).write(true).create(true).mode(0o600).custom_flags(O_NOFOLLOW).open(&path);
        let mut file = open.map_err(|error| system(path.display(), error))?;
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(lock) => return Ok(lock),
                Err((_, errno)) if Instant::now() >= deadline => return Err(system(path.display(), errno)),
                Err((returned, _)) => file = returned,
            }
            sleep(Duration::from_millis(10));
        }
    }

    fn load_state(&self) -> Option<PinState> {
        let (_, text) = read_regular_file(&self.state_file()?).ok()?;
        PinState::parse(&text)
    }

    fn save_state(&self, state: &PinState) -> Result<(), Error> {
        let dir = self.private_run_dir()?;
        let path = dir.join(format!("{}.state", self.uid));
        let write = || -> std::io::Result<()> {
            let mut file = tempfile::Builder::new().prefix(&format!(".{}.", self.uid)).tempfile_in(dir)?;
            file.write_all(state.format().as_bytes())?;
            file.persist(&path)?;
            Ok(())
        };
        write().map_err(|error| system(path.display(), error))
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
    use crate::current_uid;

    /// A scratch `etc` and `run` owned by whoever runs the tests.
    struct Scratch {
        _dir: tempfile::TempDir,
        files: UserFiles,
    }

    fn scratch() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        let uid = current_uid();
        let run_dir = dir.path().join("run");
        fs::DirBuilder::new().mode(0o700).create(&run_dir).unwrap();
        fs::set_permissions(&run_dir, Permissions::from_mode(0o700)).unwrap();
        let files = UserFiles::new(dir.path().join("etc"), uid, "tester", uid).unwrap().with_runtime(run_dir, uid);
        Scratch { _dir: dir, files }
    }

    fn write(path: &Path, text: &str, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn settings_layer_config_then_user_file() {
        let Scratch { files, .. } = &scratch();
        write(&files.config(), "max_failures = 5\nexpiry_hours = 2\n", 0o644);
        write(&files.user_file(), "hash = $y$j9T$abc$def\nmax_failures = 2\n", 0o640);
        let settings = files.settings().unwrap();
        assert_eq!((settings.max_failures, settings.expiry_hours, settings.pin_hash.as_str()), (2, 2.0, "$y$j9T$abc$def"));
    }

    #[test]
    fn untrusted_files_are_refused() {
        let Scratch { files, .. } = &scratch();
        for (mode, why) in [(0o660, "writable by its group"), (0o644, "readable by others")] {
            write(&files.user_file(), "hash = $y$x\n", mode);
            let error = files.settings().unwrap_err().to_string();
            assert!(error.contains(why), "{error}");
        }
        let other_owner = UserFiles::new(files.etc.clone(), files.etc_owner + 1, "tester", files.uid).unwrap();
        write(&files.user_file(), "hash = $y$x\n", 0o640);
        assert!(other_owner.settings().unwrap_err().to_string().contains("owned by uid"));
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let Scratch { files, .. } = &scratch();
        let real = files.etc.join("elsewhere");
        write(&real, "max_failures = 10\n", 0o644);
        symlink(&real, files.config()).unwrap();
        assert!(files.settings().is_err());
    }

    #[test]
    fn saving_a_hash_keeps_other_settings_and_sets_the_mode() {
        let Scratch { files, .. } = &scratch();
        write(&files.user_file(), "hash = $y$old\nmax_failures = 2\n", 0o640);
        files.save_pin_hash("$y$new", nix::unistd::getgid().as_raw()).unwrap();
        assert_eq!(fs::read_to_string(files.user_file()).unwrap(), "hash = $y$new\nmax_failures = 2\n");
        assert_eq!(fs::metadata(files.user_file()).unwrap().mode() & 0o777, 0o640);
        assert!(files.remove_pin().unwrap());
        assert!(!files.remove_pin().unwrap());
    }

    #[test]
    fn state_round_trips_under_the_lock() {
        let Scratch { files, .. } = &scratch();
        assert_eq!(files.load_state(), None);
        let state = PinState { boot_id: "b".into(), armed_at: 7, failures: 1 };
        let _lock = files.lock().unwrap();
        files.save_state(&state).unwrap();
        assert_eq!(files.load_state(), Some(state));
    }

    #[test]
    fn a_shared_run_dir_is_refused() {
        let Scratch { files, .. } = &scratch();
        fs::set_permissions(files.state_file().unwrap().parent().unwrap(), Permissions::from_mode(0o755)).unwrap();
        assert!(files.lock().unwrap_err().to_string().contains("not a private directory"));
    }

    #[test]
    fn a_run_dir_owned_by_someone_else_is_refused() {
        let Scratch { files, .. } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let theirs = files.clone().with_runtime(runtime.dir, runtime.owner + 1);
        assert!(theirs.lock().unwrap_err().to_string().contains("not a private directory owned by uid"));
    }

    #[test]
    fn without_a_runtime_there_is_no_state() {
        let Scratch { files, .. } = &scratch();
        let etc_only = UserFiles::new(files.etc.clone(), files.etc_owner, "tester", files.uid).unwrap();
        assert!(etc_only.lock().is_err());
        assert_eq!(etc_only.load_state(), None);
    }

    #[test]
    fn each_user_has_their_own_state() {
        let Scratch { files, .. } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let other =
            UserFiles::new(files.etc.clone(), files.etc_owner, "other", files.uid + 1).unwrap().with_runtime(runtime.dir, runtime.owner);
        let state = PinState { boot_id: "b".into(), armed_at: 7, failures: 1 };
        files.save_state(&state).unwrap();
        assert_eq!(other.load_state(), None);
        assert_ne!(files.state_file(), other.state_file());
    }

    #[test]
    fn a_held_lock_times_out_instead_of_hanging() {
        let Scratch { files, .. } = &scratch();
        let _held = files.lock().unwrap();
        let started = Instant::now();
        assert!(files.lock().is_err());
        assert!(started.elapsed() < LOCK_TIMEOUT * 2);
    }
}
