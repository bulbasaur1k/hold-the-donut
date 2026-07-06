//! Durable, live-editable user store.
//!
//! The set of allowed VLESS UUIDs is the proxy's credential check. To let
//! devices be provisioned without a restart or a redeploy, the set lives in
//! a small JSON file (the **source of truth**) fronted by a lock-free hot
//! snapshot ([`donut_core::AuthHandle`]) that the proxy reads.
//!
//! Durability: every add/remove is written through to disk **atomically and
//! fsync'd before** the in-memory snapshot is updated, so a crash can only
//! ever lose a write that never became visible to a client. On boot the file
//! is reloaded verbatim; on first boot (file absent) it is seeded from the
//! config's `inbound.users`.
//!
//! Writes are serialised by a mutex (they are rare); reads never touch it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use donut_core::{AuthHandle, UserAuth, UserId};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// One provisioned device: its credential and a little ops metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub uuid: UserId,
    /// Human label (e.g. "pixel-8"). Optional; empty when unnamed.
    #[serde(default)]
    pub name: String,
    /// Unix seconds when the record was added (0 if unknown).
    #[serde(default)]
    pub added: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum UserStoreError {
    #[error("user store i/o: {0}")]
    Io(#[from] io::Error),
    #[error("malformed user store json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("user already exists: {0}")]
    Duplicate(UserId),
}

struct Inner {
    path: PathBuf,
    records: Vec<UserRecord>,
}

/// The live user store. Clone-free: share it behind the `Arc` returned by
/// [`UserStore::load_or_seed`].
pub struct UserStore {
    handle: AuthHandle,
    inner: Mutex<Inner>,
}

impl UserStore {
    /// Load the durable store from `path`. When the file is absent (first
    /// boot) it is created and seeded from `seed` (the config's
    /// `inbound.users`). When present, the file wins — the config seed is
    /// ignored, so live edits are authoritative across redeploys.
    pub fn load_or_seed(
        path: impl Into<PathBuf>,
        seed: &[UserId],
    ) -> Result<Arc<Self>, UserStoreError> {
        let path = path.into();
        let records = if path.exists() {
            let data = fs::read(&path)?;
            serde_json::from_slice::<Vec<UserRecord>>(&data)?
        } else {
            let now = now_secs();
            let seeded: Vec<UserRecord> = seed
                .iter()
                .map(|&uuid| UserRecord {
                    uuid,
                    name: "seed".to_string(),
                    added: now,
                })
                .collect();
            persist(&path, &seeded)?;
            seeded
        };
        let handle = AuthHandle::new(auth_of(&records));
        Ok(Arc::new(Self {
            handle,
            inner: Mutex::new(Inner { path, records }),
        }))
    }

    /// A cheap, clonable read handle for the proxy hot path.
    pub fn handle(&self) -> AuthHandle {
        self.handle.clone()
    }

    /// Snapshot of the current records (for the admin `GET /admin/users`).
    pub async fn list(&self) -> Vec<UserRecord> {
        self.inner.lock().await.records.clone()
    }

    /// Add a device. Mints a fresh v4 UUID when `uuid` is `None`. The new
    /// set is persisted (atomic + fsync) **before** the live snapshot is
    /// swapped, so an authorised client can never race ahead of durability.
    pub async fn add(
        &self,
        name: String,
        uuid: Option<UserId>,
    ) -> Result<UserRecord, UserStoreError> {
        let mut inner = self.inner.lock().await;
        let uuid = uuid.unwrap_or_else(UserId::new_v4);
        if inner.records.iter().any(|r| r.uuid == uuid) {
            return Err(UserStoreError::Duplicate(uuid));
        }
        let record = UserRecord {
            uuid,
            name,
            added: now_secs(),
        };
        // Build the candidate, persist it, and only then commit in-memory —
        // a failed write leaves both disk and memory untouched.
        let mut candidate = inner.records.clone();
        candidate.push(record.clone());
        persist(&inner.path, &candidate)?;
        inner.records = candidate;
        self.handle.store(auth_of(&inner.records));
        Ok(record)
    }

    /// Remove a device by UUID. Returns whether a record was actually
    /// removed. Persisted before the snapshot swap, same as [`add`].
    pub async fn remove(&self, uuid: &UserId) -> Result<bool, UserStoreError> {
        let mut inner = self.inner.lock().await;
        let mut candidate = inner.records.clone();
        candidate.retain(|r| &r.uuid != uuid);
        if candidate.len() == inner.records.len() {
            return Ok(false);
        }
        persist(&inner.path, &candidate)?;
        inner.records = candidate;
        self.handle.store(auth_of(&inner.records));
        Ok(true)
    }
}

fn auth_of(records: &[UserRecord]) -> UserAuth {
    UserAuth::new(records.iter().map(|r| r.uuid).collect())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Atomically replace `path` with `records`: write a sibling temp file,
/// fsync its contents, chmod 0640, rename over the target, then fsync the
/// directory so the rename itself survives a power loss.
fn persist(path: &Path, records: &[UserRecord]) -> Result<(), UserStoreError> {
    let data = serde_json::to_vec_pretty(records)?;
    let tmp = tmp_path(path);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    set_owner_only(&tmp);
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(unix)]
fn set_owner_only(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o640));
}

#[cfg(not(unix))]
fn set_owner_only(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(s: &str) -> UserId {
        s.parse().unwrap()
    }

    fn tmp_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        // Unique-ish without Date/rand: nanos since boot via a monotonic-ish
        // source is unavailable in tests deterministically, so use the file
        // count + a pid to avoid collisions across parallel test binaries.
        p.push(format!("donut-users-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&p);
        p
    }

    #[tokio::test]
    async fn seeds_when_absent_then_reloads() {
        let dir = tmp_dir();
        let path = dir.join("seed.json");
        let _ = fs::remove_file(&path);
        let seed = vec![uid("ba62af9d-8c38-4a4f-8cb4-0e8941d5c9bc")];

        let store = UserStore::load_or_seed(&path, &seed).unwrap();
        assert_eq!(store.handle().len(), 1);
        assert!(store.handle().is_authorized(&seed[0]));
        assert!(path.exists(), "seed must be persisted on first boot");

        // Reload: the file wins, the (now-empty) seed is ignored.
        let reloaded = UserStore::load_or_seed(&path, &[]).unwrap();
        assert_eq!(reloaded.handle().len(), 1);
        assert!(reloaded.handle().is_authorized(&seed[0]));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn add_authorises_live_and_survives_reload() {
        let dir = tmp_dir();
        let path = dir.join("add.json");
        let _ = fs::remove_file(&path);
        let store = UserStore::load_or_seed(&path, &[]).unwrap();
        let handle = store.handle();
        assert!(handle.is_empty());

        let rec = store.add("pixel-8".into(), None).await.unwrap();
        // The SAME handle taken before the add now authorises the new UUID —
        // no restart, no re-fetch of the handle.
        assert!(handle.is_authorized(&rec.uuid));
        assert_eq!(handle.len(), 1);

        // Durability: a fresh load from disk sees it.
        let reloaded = UserStore::load_or_seed(&path, &[]).unwrap();
        assert!(reloaded.handle().is_authorized(&rec.uuid));

        // Duplicate is rejected.
        assert!(matches!(
            store.add("dup".into(), Some(rec.uuid)).await,
            Err(UserStoreError::Duplicate(_))
        ));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn remove_deauthorises_live_and_survives_reload() {
        let dir = tmp_dir();
        let path = dir.join("remove.json");
        let _ = fs::remove_file(&path);
        let store = UserStore::load_or_seed(&path, &[]).unwrap();
        let handle = store.handle();
        let rec = store.add("mac".into(), None).await.unwrap();
        assert!(handle.is_authorized(&rec.uuid));

        assert!(store.remove(&rec.uuid).await.unwrap());
        assert!(!handle.is_authorized(&rec.uuid));
        assert!(
            !store.remove(&rec.uuid).await.unwrap(),
            "second remove is a no-op"
        );

        let reloaded = UserStore::load_or_seed(&path, &[]).unwrap();
        assert!(!reloaded.handle().is_authorized(&rec.uuid));
        let _ = fs::remove_file(&path);
    }
}
