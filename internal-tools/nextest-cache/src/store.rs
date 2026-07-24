// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-key cache storage for the reference provider.

use crate::error::CacheError;
use atomicwrites::{AllowOverwrite, AtomicFile};
use etcetera::{BaseStrategy, choose_base_strategy};
use nextest_runner::cache_protocol::{CommitDisposition, CommitUpdate};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env,
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

pub(crate) const CACHE_DIR_ENV: &str = "NEXTEST_CACHE_DIR";
const STORAGE_VERSION_DIR: &str = "storage-v1";
const ENTRY_VERSION: u32 = 1;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub(crate) struct CacheStore {
    root: PathBuf,
}

impl CacheStore {
    pub(crate) fn discover() -> Result<Self, CacheError> {
        let base = match env::var_os(CACHE_DIR_ENV) {
            Some(path) => PathBuf::from(path),
            None => choose_base_strategy()
                .map_err(|error| CacheError::CacheDirectory(error.to_string()))?
                .cache_dir()
                .join("nextest")
                .join("cache"),
        };
        Ok(Self {
            root: base.join(STORAGE_VERSION_DIR),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_root(root: PathBuf) -> Self {
        Self {
            root: root.join(STORAGE_VERSION_DIR),
        }
    }

    pub(crate) fn contains_valid(&self, token: &str) -> Result<bool, CacheError> {
        validate_token(token)?;
        let path = self.entry_path(token);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(CacheError::io(
                    format!("failed to read cache entry {}", path.display()),
                    error,
                ));
            }
        };

        let Ok(entry) = serde_json::from_slice::<CacheEntry>(&bytes) else {
            return Ok(false);
        };
        Ok(entry.version == ENTRY_VERSION)
    }

    pub(crate) fn apply_updates(&self, updates: &[CommitUpdate]) -> Result<(), CacheError> {
        validate_updates(updates)?;

        let mut failures = Vec::new();
        for disposition in [CommitDisposition::Invalidate, CommitDisposition::CleanPass] {
            for update in updates
                .iter()
                .filter(|update| update.disposition == disposition)
            {
                let result = match disposition {
                    CommitDisposition::Invalidate => self.invalidate(&update.token),
                    CommitDisposition::CleanPass => self.store_clean_pass(&update.token),
                    CommitDisposition::Hit => unreachable!("hits are not persisted"),
                };
                if let Err(error) = result {
                    failures.push(format!("test ID {}: {error}", update.test_id));
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(CacheError::UpdateFailures(failures.join("; ")))
        }
    }

    fn store_clean_pass(&self, token: &str) -> Result<(), CacheError> {
        self.with_key_lock(token, || {
            let path = self.entry_path(token);
            let parent = path.parent().expect("entry path has a parent");
            fs::create_dir_all(parent).map_err(|error| {
                CacheError::io(
                    format!(
                        "failed to create cache entry directory {}",
                        parent.display()
                    ),
                    error,
                )
            })?;

            let entry = CacheEntry {
                version: ENTRY_VERSION,
            };
            AtomicFile::new(&path, AllowOverwrite)
                .write(|file| -> io::Result<()> {
                    serde_json::to_writer(file, &entry).map_err(io::Error::other)?;
                    Ok(())
                })
                .map_err(|error| CacheError::AtomicWrite(error.to_string()))
        })
    }

    fn invalidate(&self, token: &str) -> Result<(), CacheError> {
        self.with_key_lock(token, || {
            let path = self.entry_path(token);
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(CacheError::io(
                    format!("failed to remove cache entry {}", path.display()),
                    error,
                )),
            }
        })
    }

    fn with_key_lock<T>(
        &self,
        token: &str,
        operation: impl FnOnce() -> Result<T, CacheError>,
    ) -> Result<T, CacheError> {
        let lock_path = self.lock_path(token);
        let parent = lock_path.parent().expect("lock path has a parent");
        fs::create_dir_all(parent).map_err(|error| {
            CacheError::io(
                format!("failed to create cache lock directory {}", parent.display()),
                error,
            )
        })?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                CacheError::io(
                    format!("failed to open cache lock {}", lock_path.display()),
                    error,
                )
            })?;
        acquire_lock(&lock)?;
        operation()
    }

    fn entry_path(&self, token: &str) -> PathBuf {
        self.root
            .join("entries")
            .join(&token[..2])
            .join(format!("{token}.json"))
    }

    fn lock_path(&self, token: &str) -> PathBuf {
        self.root
            .join("locks")
            .join(&token[..2])
            .join(format!("{token}.lock"))
    }

    #[cfg(test)]
    pub(crate) fn entry_path_for_test(&self, token: &str) -> PathBuf {
        self.entry_path(token)
    }
}

fn acquire_lock(file: &File) -> Result<(), CacheError> {
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                if started.elapsed() >= LOCK_TIMEOUT {
                    return Err(CacheError::LockTimeout(LOCK_TIMEOUT));
                }
                thread::sleep(LOCK_RETRY_INTERVAL);
            }
            Err(TryLockError::Error(error)) => {
                return Err(CacheError::io("failed to lock cache entry", error));
            }
        }
    }
}

fn validate_updates(updates: &[CommitUpdate]) -> Result<(), CacheError> {
    let mut test_ids = HashSet::with_capacity(updates.len());
    let mut tokens = HashSet::with_capacity(updates.len());
    for update in updates {
        if !test_ids.insert(update.test_id) {
            return Err(CacheError::InvalidRequest(format!(
                "duplicate commit test ID {}",
                update.test_id
            )));
        }
        validate_token(&update.token)?;
        if !tokens.insert(update.token.as_str()) {
            return Err(CacheError::InvalidRequest(format!(
                "duplicate commit token {}",
                update.token
            )));
        }
        if update.execution.effect_ledger.is_some() {
            return Err(CacheError::InvalidRequest(format!(
                "test ID {} included an effect ledger unsupported by protocol version 1",
                update.test_id
            )));
        }
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), CacheError> {
    if token.len() != 64
        || !token
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(CacheError::InvalidRequest(
            "cache token must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct CacheEntry {
    version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextest_runner::cache_protocol::{CacheExecutionData, CommitUpdate};
    use std::sync::{Arc, Barrier};

    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn update(disposition: CommitDisposition) -> CommitUpdate {
        update_for(1, TOKEN, disposition)
    }

    fn update_for(test_id: u64, token: &str, disposition: CommitDisposition) -> CommitUpdate {
        CommitUpdate {
            test_id,
            token: token.to_owned(),
            disposition,
            execution: CacheExecutionData::default(),
        }
    }

    #[test]
    fn clean_pass_hit_and_invalidate() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());

        assert!(!store.contains_valid(TOKEN).unwrap());
        store
            .apply_updates(&[update(CommitDisposition::CleanPass)])
            .unwrap();
        assert!(store.contains_valid(TOKEN).unwrap());
        store
            .apply_updates(&[update(CommitDisposition::Invalidate)])
            .unwrap();
        assert!(!store.contains_valid(TOKEN).unwrap());
    }

    #[test]
    fn corrupt_and_unknown_entries_are_misses() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());
        let path = store.entry_path_for_test(TOKEN);
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        fs::write(&path, b"not json").unwrap();
        assert!(!store.contains_valid(TOKEN).unwrap());
        fs::write(&path, br#"{"version":999}"#).unwrap();
        assert!(!store.contains_valid(TOKEN).unwrap());
    }

    #[test]
    fn concurrent_commits_never_produce_a_partial_entry() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = Arc::new(CacheStore::from_root(temp.path().into()));
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let barrier = barrier.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                store
                    .apply_updates(&[update(CommitDisposition::CleanPass)])
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(store.contains_valid(TOKEN).unwrap());
    }

    #[test]
    fn update_failure_does_not_skip_invalidation() {
        const INVALIDATED_TOKEN: &str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());
        store
            .apply_updates(&[update_for(
                2,
                INVALIDATED_TOKEN,
                CommitDisposition::CleanPass,
            )])
            .unwrap();
        assert!(store.contains_valid(INVALIDATED_TOKEN).unwrap());

        // Make only TOKEN's lock prefix unusable, leaving INVALIDATED_TOKEN's
        // independent prefix available.
        let bad_lock_parent = store.lock_path(TOKEN).parent().unwrap().to_owned();
        fs::create_dir_all(bad_lock_parent.parent().unwrap()).unwrap();
        fs::write(&bad_lock_parent, b"not a directory").unwrap();

        let error = store
            .apply_updates(&[
                update_for(1, TOKEN, CommitDisposition::CleanPass),
                update_for(2, INVALIDATED_TOKEN, CommitDisposition::Invalidate),
            ])
            .unwrap_err();

        assert!(matches!(error, CacheError::UpdateFailures(_)));
        assert!(!store.contains_valid(INVALIDATED_TOKEN).unwrap());
    }

    #[test]
    fn validation_happens_before_any_update() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());
        let mut invalid = update(CommitDisposition::CleanPass);
        invalid.test_id = 2;
        invalid.token = "invalid".to_owned();

        assert!(
            store
                .apply_updates(&[update(CommitDisposition::CleanPass), invalid])
                .is_err()
        );
        assert!(!store.contains_valid(TOKEN).unwrap());
    }
}
