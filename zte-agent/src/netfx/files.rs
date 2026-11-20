//! Private runtime files: 0700 directories, 0600 files written atomically.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// The identity of a database file as last hashed. A replacement (new inode),
/// a size change or any rewrite (which moves the change time) re-hashes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    dev: u64,
    ino: u64,
    pub(crate) len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    pub(crate) fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

pub fn private_dir(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| e.to_string())?;
    if fs::metadata(path).map_err(|e| e.to_string())?.mode() & 0o7777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Invalid private path")?;
    private_dir(parent)?;
    let tmp = path.with_extension("new");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_file_is_private_and_atomic() {
        let dir = std::env::temp_dir().join(format!("u60-private-{}", std::process::id()));
        let path = dir.join("config.json");
        write_private(&path, b"secret").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        fs::remove_dir_all(dir).unwrap();
    }
}
