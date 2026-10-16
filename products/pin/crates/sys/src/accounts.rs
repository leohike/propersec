use std::path::Path;

use nix::unistd::{Group, Uid, User, getegid, geteuid, getgid, getuid};
use properpin_core::Error;

use crate::system;

/// A user account from the passwd database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

impl Account {
    pub fn by_uid(uid: u32) -> Result<Self, Error> {
        let user = User::from_uid(Uid::from_raw(uid)).map_err(|error| system(format!("uid {uid}"), error))?;
        user.map(Self::from).ok_or_else(|| Error::System(format!("no user with uid {uid}")))
    }

    pub fn by_name(name: &str) -> Result<Self, Error> {
        let user = User::from_name(name).map_err(|error| system(format!("user {name:?}"), error))?;
        user.map(Self::from).ok_or_else(|| Error::System(format!("no user named {name:?}")))
    }
}

impl From<User> for Account {
    fn from(user: User) -> Self {
        Self { name: user.name, uid: user.uid.as_raw(), gid: user.gid.as_raw() }
    }
}

pub fn current_uid() -> u32 {
    getuid().as_raw()
}

pub fn current_euid() -> u32 {
    geteuid().as_raw()
}

pub fn current_gid() -> u32 {
    getgid().as_raw()
}

pub fn current_egid() -> u32 {
    getegid().as_raw()
}

/// The gid of the group named `name`, or of `name` itself when it is a number.
pub fn group_by_name(name: &str) -> Result<u32, Error> {
    if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
        return name.parse().map_err(|error| system(format!("group {name:?}"), error));
    }
    let group = Group::from_name(name).map_err(|error| system(format!("group {name:?}"), error))?;
    group.map(|group| group.gid.as_raw()).ok_or_else(|| Error::System(format!("no group named {name:?}")))
}

/// `user`'s password hash, the second field of their line in the shadow file at `path`
/// (`/etc/shadow`, which only root can read), or `None` when they have no line there, as with LDAP
/// or systemd-homed accounts.
pub fn shadow_hash(path: &Path, user: &str) -> Result<Option<String>, Error> {
    let text = std::fs::read_to_string(path).map_err(|error| system(path.display(), error))?;
    let hash = text.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(user)).then(|| fields.next().unwrap_or_default().to_owned())
    });
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_current_user_both_ways() {
        let me = Account::by_uid(current_uid()).unwrap();
        assert_eq!(Account::by_name(&me.name).unwrap(), me);
        assert!(Account::by_name("no-such-user-properpin").is_err());
    }

    #[test]
    fn finds_groups_by_name_or_number() {
        assert_eq!(group_by_name("root").unwrap(), 0);
        assert_eq!(group_by_name("4242").unwrap(), 4242);
        assert!(group_by_name("no-such-group-properpin").is_err());
    }

    #[test]
    fn reads_a_users_shadow_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");
        std::fs::write(&path, "root:!locked::0:99999:7:::\nalice:$y$j9T$salt$hash:20000:0:99999:7:::\nbob::20000::::::\n").unwrap();
        assert_eq!(shadow_hash(&path, "alice").unwrap().as_deref(), Some("$y$j9T$salt$hash"));
        assert_eq!(shadow_hash(&path, "bob").unwrap().as_deref(), Some(""));
        assert_eq!(shadow_hash(&path, "ali").unwrap(), None);
        assert!(shadow_hash(&dir.path().join("missing"), "alice").is_err());
    }
}
