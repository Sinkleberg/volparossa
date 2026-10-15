//! Best-effort cache advice for one owner-authorized, unchanged native GGUF.
//! This is not memory admission, guaranteed reclaim, or evidence of a cache cause.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::Result;
use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};

use super::super::{ModelProfile, private_directory, resources, spare_capacity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    fn read(info: &Metadata) -> Self {
        Self {
            device: info.dev(),
            inode: info.ino(),
            owner: info.uid(),
            links: info.nlink(),
            mode: info.mode(),
            bytes: info.len(),
            modified: (info.mtime(), info.mtime_nsec()),
            changed: (info.ctime(), info.ctime_nsec()),
        }
    }

    fn valid(self, expected_bytes: u64) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
            && self.owner == nix::unistd::geteuid().as_raw()
            && self.links == 1
            && self.mode & 0o077 == 0
            && self.bytes == expected_bytes
            && (1..=9 * 1024 * 1024 * 1024).contains(&self.bytes)
    }
}

pub(in crate::compute) struct CacheHint {
    file: File,
    root: PathBuf,
    root_identity: (u64, u64),
    identity: Identity,
}

impl CacheHint {
    // Called only from a request already bound to the owner's manifest digest.
    pub(super) fn bind(root: &Path, expected_bytes: u64) -> Option<Self> {
        private_directory(root).ok()?;
        let directory = fs::symlink_metadata(root).ok()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(root.join("model.gguf"))
            .ok()?;
        let identity = Identity::read(&file.metadata().ok()?);
        if !identity.valid(expected_bytes) {
            return None;
        }
        let hint = Self {
            file,
            root: root.to_owned(),
            root_identity: (directory.dev(), directory.ino()),
            identity,
        };
        hint.unchanged().then_some(hint)
    }

    fn unchanged(&self) -> bool {
        let check = || -> Option<bool> {
            private_directory(&self.root).ok()?;
            let directory = fs::symlink_metadata(&self.root).ok()?;
            let descriptor = Identity::read(&self.file.metadata().ok()?);
            let path = Identity::read(&fs::symlink_metadata(self.root.join("model.gguf")).ok()?);
            Some(
                (directory.dev(), directory.ino()) == self.root_identity
                    && descriptor.valid(self.identity.bytes)
                    && descriptor == self.identity
                    && path == self.identity,
            )
        };
        check() == Some(true)
    }

    pub(in crate::compute) fn after_supervisor<T>(self, result: &Result<T>, profile: ModelProfile) {
        self.after_supervisor_with(
            result,
            profile,
            spare_capacity::memory_headroom,
            |file, bytes| posix_fadvise(file, 0, bytes, PosixFadviseAdvice::POSIX_FADV_DONTNEED),
        );
    }

    fn after_supervisor_with<T>(
        self,
        result: &Result<T>,
        profile: ModelProfile,
        headroom: impl FnOnce() -> Option<u64>,
        advise: impl FnOnce(&File, libc::off_t) -> nix::Result<()>,
    ) {
        if result.is_err() || !needs_hint(profile, headroom()) || !self.unchanged() {
            return;
        }
        if let Ok(bytes) = libc::off_t::try_from(self.identity.bytes) {
            // One bounded file range, no retries, reads, rehash, or global reclaim.
            // Advisory success does not prove freed memory. The syscall may take
            // time; keep it synchronous under the existing runtime lease.
            let _ = advise(&self.file, bytes);
        }
    }
}

fn needs_hint(profile: ModelProfile, headroom: Option<u64>) -> bool {
    profile == ModelProfile::Qwen4bInstruct2507
        && headroom.is_some_and(|available| {
            resources::limits(profile)
                .admission_headroom
                .is_some_and(|required| available < required)
        })
}

#[cfg(test)]
mod tests;
