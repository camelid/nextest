// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Race-checked file content and metadata fingerprints.

use serde::{Deserialize, Serialize};
use std::{io, path::Path};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FileFingerprint {
    content_xxh3_128: String,
    metadata_xxh3_128: String,
}

pub(crate) fn fingerprint_file(path: &Path) -> io::Result<FileFingerprint> {
    imp::fingerprint_file(path)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::FileFingerprint;
    use std::{
        ffi::{CString, OsString},
        fs::{self, File},
        io::{self, Read},
        mem::{self, MaybeUninit},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
        path::{Path, PathBuf},
        slice,
    };
    use xxhash_rust::xxh3::Xxh3;

    const HASH_BUFFER_SIZE: usize = 256 * 1024;
    const STATX_REQUEST_MASK: libc::c_uint = 0x0003_ffff;
    const METADATA_DOMAIN: &[u8] = b"nextest-cache-file-metadata-v1";

    pub(super) fn fingerprint_file(path: &Path) -> io::Result<FileFingerprint> {
        fingerprint_file_with(path, || {})
    }

    fn fingerprint_file_with(
        path: &Path,
        after_read: impl FnOnce(),
    ) -> io::Result<FileFingerprint> {
        let initial_path = statx_path(path, libc::AT_SYMLINK_NOFOLLOW)?;
        let link_before = read_link_if_needed(path, initial_path.mode)?;
        let path_before = statx_path(path, libc::AT_SYMLINK_NOFOLLOW)?;
        let target_before = statx_path(path, 0)?;

        let c_path = c_path(path)?;
        // SAFETY: `c_path` is NUL-terminated, and the flags do not require a mode argument.
        let descriptor = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOATIME,
            )
        };
        if descriptor == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `descriptor` was just returned by `open` and is now owned by `file`.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let descriptor_before = statx_descriptor(file.as_raw_fd())?;
        if descriptor_before.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the input is not a regular file",
            ));
        }
        if descriptor_before != target_before {
            return Err(input_changed());
        }

        let mut content = Xxh3::new();
        let mut buffer = vec![0; HASH_BUFFER_SIZE];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => content.update(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }

        after_read();
        let descriptor_after = statx_descriptor(file.as_raw_fd())?;
        let target_after = statx_path(path, 0)?;
        let link_after = read_link_if_needed(path, path_before.mode)?;
        let path_after = statx_path(path, libc::AT_SYMLINK_NOFOLLOW)?;
        if descriptor_after != descriptor_before
            || target_after != target_before
            || path_after != path_before
            || link_after != link_before
        {
            return Err(input_changed());
        }

        let mut metadata = Xxh3::new();
        update_field(&mut metadata, METADATA_DOMAIN);
        update_field(&mut metadata, &path_before.bytes);
        update_field(&mut metadata, &target_before.bytes);
        if let Some(link) = link_before {
            update_field(&mut metadata, link.as_encoded_bytes());
        } else {
            update_field(&mut metadata, &[]);
        }

        Ok(FileFingerprint {
            content_xxh3_128: hex::encode(content.digest128().to_be_bytes()),
            metadata_xxh3_128: hex::encode(metadata.digest128().to_be_bytes()),
        })
    }

    fn statx_path(path: &Path, flags: libc::c_int) -> io::Result<StatxSnapshot> {
        let path = c_path(path)?;
        statx(libc::AT_FDCWD, &path, flags)
    }

    fn statx_descriptor(descriptor: libc::c_int) -> io::Result<StatxSnapshot> {
        let empty = c"";
        statx(descriptor, empty, libc::AT_EMPTY_PATH)
    }

    fn statx(
        descriptor: libc::c_int,
        path: &std::ffi::CStr,
        flags: libc::c_int,
    ) -> io::Result<StatxSnapshot> {
        let mut metadata = MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: `path` is NUL-terminated, and `metadata` points to a writable statx buffer.
        let status = unsafe {
            libc::statx(
                descriptor,
                path.as_ptr(),
                flags,
                STATX_REQUEST_MASK,
                metadata.as_mut_ptr(),
            )
        };
        if status == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: The buffer was zero-initialized, and `statx` completed successfully.
        let metadata = unsafe { metadata.assume_init() };
        // SAFETY: Every byte in `metadata` is initialized, and the slice has its exact size.
        let bytes = unsafe {
            slice::from_raw_parts(
                (&raw const metadata).cast::<u8>(),
                mem::size_of::<libc::statx>(),
            )
        }
        .to_vec();
        Ok(StatxSnapshot {
            mode: metadata.stx_mode as libc::mode_t,
            bytes,
        })
    }

    fn read_link_if_needed(path: &Path, mode: libc::mode_t) -> io::Result<Option<OsString>> {
        if mode & libc::S_IFMT == libc::S_IFLNK {
            fs::read_link(path).map(PathBuf::into_os_string).map(Some)
        } else {
            Ok(None)
        }
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the input path contains a NUL byte",
            )
        })
    }

    fn update_field(hasher: &mut Xxh3, value: &[u8]) {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    fn input_changed() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the input changed while it was fingerprinted",
        )
    }

    #[derive(Eq, PartialEq)]
    struct StatxSnapshot {
        mode: libc::mode_t,
        bytes: Vec<u8>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs::{FileTimes, Permissions},
            os::unix::fs::{MetadataExt, PermissionsExt},
            time::{Duration, UNIX_EPOCH},
        };

        #[test]
        fn content_and_metadata_changes_have_distinct_fingerprints() {
            let temp = camino_tempfile::tempdir().unwrap();
            let input = temp.path().join("input");
            fs::write(&input, b"first").unwrap();

            let initial = fingerprint_file(input.as_std_path()).unwrap();
            let mode = fs::metadata(&input).unwrap().permissions().mode();
            fs::set_permissions(&input, Permissions::from_mode(mode ^ 0o100)).unwrap();
            let changed_mode = fingerprint_file(input.as_std_path()).unwrap();
            assert_eq!(initial.content_xxh3_128, changed_mode.content_xxh3_128);
            assert_ne!(initial.metadata_xxh3_128, changed_mode.metadata_xxh3_128);

            let file = File::open(&input).unwrap();
            file.set_times(
                FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000)),
            )
            .unwrap();
            let changed_time = fingerprint_file(input.as_std_path()).unwrap();
            assert_eq!(changed_mode.content_xxh3_128, changed_time.content_xxh3_128);
            assert_ne!(
                changed_mode.metadata_xxh3_128,
                changed_time.metadata_xxh3_128
            );
        }

        #[test]
        fn fingerprinting_does_not_update_access_time() {
            let temp = camino_tempfile::tempdir().unwrap();
            let input = temp.path().join("input");
            fs::write(&input, b"input").unwrap();
            let before = fs::metadata(&input).unwrap();

            fingerprint_file(input.as_std_path()).unwrap();

            let after = fs::metadata(&input).unwrap();
            assert_eq!(
                (before.atime(), before.atime_nsec()),
                (after.atime(), after.atime_nsec()),
            );
        }

        #[test]
        fn inputs_changing_while_hashed_are_rejected() {
            let temp = camino_tempfile::tempdir().unwrap();
            let input = temp.path().join("input");
            fs::write(&input, b"first").unwrap();

            assert!(
                fingerprint_file_with(input.as_std_path(), || {
                    fs::write(&input, b"second").unwrap()
                })
                .is_err(),
            );
        }

        #[test]
        fn symlink_text_is_part_of_the_metadata_fingerprint() {
            use std::os::unix::fs::symlink;

            let temp = camino_tempfile::tempdir().unwrap();
            let first = temp.path().join("first");
            let second = temp.path().join("second");
            let input = temp.path().join("input");
            fs::write(&first, b"same").unwrap();
            fs::write(&second, b"same").unwrap();
            symlink(&first, &input).unwrap();
            let initial = fingerprint_file(input.as_std_path()).unwrap();

            fs::remove_file(&input).unwrap();
            symlink(&second, &input).unwrap();
            let changed = fingerprint_file(input.as_std_path()).unwrap();

            assert_eq!(initial.content_xxh3_128, changed.content_xxh3_128);
            assert_ne!(initial.metadata_xxh3_128, changed.metadata_xxh3_128);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::FileFingerprint;
    use std::{io, path::Path};

    pub(super) fn fingerprint_file(_path: &Path) -> io::Result<FileFingerprint> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "complete file metadata fingerprints are only supported on Linux",
        ))
    }
}
