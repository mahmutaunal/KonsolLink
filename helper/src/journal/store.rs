use super::{Error, Journal, Result};
use std::{
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

const MAX_BYTES: u64 = 64 * 1024;
const JOURNAL: &CStr = c"journal.json";
const NEXT: &CStr = c"journal.next";
#[cfg(any(target_os = "macos", test))]
const LOCK: &CStr = c"helper.lock";

/// Non-cloneable lifetime lock plus directory FD. Lock inode is never renamed
/// or removed. Journal paths cannot be supplied by IPC or the CLI.
pub struct Store {
    directory: File,
    _lock: File,
    owner: u32,
    poisoned: bool,
    #[cfg(test)]
    pub(super) fail_save: bool,
    #[cfg(test)]
    pub(super) fail_save_number: Option<usize>,
    #[cfg(test)]
    pub(super) crash_at: Option<(usize, u8)>,
    #[cfg(test)]
    saves: usize,
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: libc::c_uint) -> std::io::Result<File> {
    // SAFETY: directory is live, name is NUL-terminated, returned fd is owned.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "macos")]
fn reject_acl(file: &File) -> Result<()> {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry: i32, result: *mut *mut c_void) -> i32;
        fn acl_free(acl: *mut c_void) -> i32;
    }
    // SAFETY: the fd is valid; constants from the macOS sys/acl.h ABI.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        // Darwin reports ENOENT when this existing descriptor has no extended
        // ACL. Do not confuse a disappeared object with an absent ACL.
        if error.raw_os_error() == Some(libc::ENOENT) && file.metadata()?.nlink() > 0 {
            return Ok(());
        }
        return Err(error.into());
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: acl is owned and entry is a valid out parameter.
    let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = std::io::Error::last_os_error();
    // SAFETY: release the ACL exactly once after access is finished.
    if unsafe { acl_free(acl) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if status == 0 {
        return Err(Error::Unsafe("extended ACL entries are not accepted"));
    }
    if error.raw_os_error() != Some(libc::EINVAL) {
        return Err(error.into());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn reject_acl(_: &File) -> Result<()> {
    Ok(())
} // Production opener is macOS-only.

fn verify(file: &File, owner: u32, directory: bool, private: bool) -> Result<()> {
    let meta = file.metadata()?;
    if meta.uid() != owner {
        return Err(Error::Unsafe("unexpected owner"));
    }
    if directory {
        if !meta.is_dir() {
            return Err(Error::Unsafe("not a directory"));
        }
        if (private && meta.mode() & 0o7777 != 0o700) || (!private && meta.mode() & 0o022 != 0) {
            return Err(Error::Unsafe("directory permissions"));
        }
    } else if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        return Err(Error::Unsafe("file type, permissions or hard link"));
    }
    reject_acl(file)
}

fn durable(file: &File) -> Result<()> {
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    {
        // SAFETY: F_FULLFSYNC needs no variadic argument; file is a valid fd.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

impl Store {
    /// Fixed root-owned location. Rejects insecure ancestors, symlinks and ACLs.
    /// Does not elevate privileges or modify networking.
    pub fn open_system() -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: geteuid has no arguments or memory preconditions.
            if unsafe { libc::geteuid() } != 0 {
                return Err(Error::Unsafe("root required for system journal"));
            }
            let mut directory = File::open("/")?;
            verify(&directory, 0, true, false)?;
            for component in [c"private", c"var", c"db"] {
                directory = open_at(&directory, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                verify(&directory, 0, true, false)?;
            }
            // SAFETY: a validated parent fd and fixed single-component name.
            if unsafe { libc::mkdirat(directory.as_raw_fd(), c"konsollink".as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            }
            directory.sync_all()?;
            let private = open_at(
                &directory,
                c"konsollink",
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            Self::open_directory(private, 0)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(Error::Unsafe("system journal is only qualified for macOS"))
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn open_directory(directory: File, owner: u32) -> Result<Self> {
        verify(&directory, owner, true, true)?;
        let lock = open_at(&directory, LOCK, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        verify(&lock, owner, false, true)?;
        // SAFETY: live regular fd; nonblocking exclusive lock held by this File.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(Error::Locked);
            }
            return Err(error.into());
        }
        directory.sync_all()?;
        let mut store = Self {
            directory,
            _lock: lock,
            owner,
            poisoned: false,
            #[cfg(test)]
            fail_save: false,
            #[cfg(test)]
            fail_save_number: None,
            #[cfg(test)]
            crash_at: None,
            #[cfg(test)]
            saves: 0,
        };
        store.load()?; // Corruption blocks startup before stale-file cleanup.
        store.remove_next()?;
        Ok(store)
    }

    fn check(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        verify(&self.directory, self.owner, true, true)
    }

    pub fn load(&self) -> Result<Option<Journal>> {
        self.check()?;
        let file = match open_at(&self.directory, JOURNAL, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        verify(&file, self.owner, false, true)?;
        if file.metadata()?.len() > MAX_BYTES {
            return Err(Error::Invalid("journal size limit"));
        }
        let mut data = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_BYTES {
            return Err(Error::Invalid("journal size limit"));
        }
        let journal: Journal = serde_json::from_slice(&data)?;
        journal.validate()?;
        Ok(Some(journal))
    }

    fn remove_next(&mut self) -> Result<()> {
        match open_at(&self.directory, NEXT, libc::O_RDONLY, 0) {
            Ok(file) => verify(&file, self.owner, false, true)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        // SAFETY: fixed name inside the owned locked directory; never recursive.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), NEXT.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        Ok(())
    }

    pub(super) fn save(&mut self, journal: &Journal) -> Result<()> {
        self.check()?;
        journal.validate()?;
        let data = serde_json::to_vec(journal)?;
        if data.len() as u64 > MAX_BYTES {
            return Err(Error::Invalid("journal size limit"));
        }
        #[cfg(test)]
        {
            self.saves += 1;
        }
        let result = (|| {
            #[cfg(test)]
            if self.fail_save || self.fail_save_number == Some(self.saves) {
                return Err(Error::Io(std::io::Error::other(
                    "injected persistence failure",
                )));
            }
            // Recheck existing evidence before replacing it; never overwrite an
            // unrecognized/corrupt journal to make startup look successful.
            self.load()?;
            self.remove_next()?;
            let mut file = open_at(
                &self.directory,
                NEXT,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            verify(&file, self.owner, false, true)?;
            file.write_all(&data)?;
            #[cfg(test)]
            self.crash_checkpoint(1);
            durable(&file)?;
            #[cfg(test)]
            self.crash_checkpoint(2);
            // SAFETY: both fixed single-component names use the same directory fd.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    NEXT.as_ptr(),
                    self.directory.as_raw_fd(),
                    JOURNAL.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            #[cfg(test)]
            self.crash_checkpoint(3);
            self.directory.sync_all()?;
            // On macOS also request a media flush after the rename/dir sync.
            durable(&file)?;
            #[cfg(test)]
            self.crash_checkpoint(4);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

#[cfg(test)]
impl Store {
    fn crash_checkpoint(&self, point: u8) {
        if self.crash_at == Some((self.saves, point)) {
            std::process::exit(77);
        }
    }
    pub(crate) fn open_test(path: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        // SAFETY: no preconditions for geteuid. This entry point is test-only.
        Self::open_directory(directory, unsafe { libc::geteuid() })
    }

    pub(crate) fn fail_save_in(&mut self, additional_saves: usize) {
        self.fail_save_number = self.saves.checked_add(additional_saves);
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_socket_ancestor(path: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    verify(&file, 0, true, false)
}
