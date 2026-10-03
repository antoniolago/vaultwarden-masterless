use chrono::{NaiveDateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

use crate::errors::{AppError, AppResult};
use crate::models::StoredKeyEntry;

/// SQLite-backed database for user key storage and application data.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &str) -> AppResult<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::DatabaseError(format!("Cannot create data dir: {e}")))?;
        }

        // Set restrictive umask before creating DB so it's not world-readable
        #[cfg(unix)]
        let _old_umask = unsafe { libc::umask(0o077) };

        let conn = Connection::open(path)
            .map_err(|e| AppError::DatabaseError(format!("Cannot open database: {e}")))?;

        // Restore previous umask
        #[cfg(unix)]
        unsafe { libc::umask(_old_umask); }

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| AppError::DatabaseError(format!("PRAGMA failed: {e}")))?;

        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Create tables if they don't exist.
    fn migrate(&self) -> AppResult<()> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS user_keys (
                user_id     TEXT PRIMARY KEY NOT NULL,
                encrypted_key BLOB NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                last_access_at TEXT
            );

            CREATE TABLE IF NOT EXISTS app_data (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );",
        )
        .map_err(|e| AppError::DatabaseError(format!("Migration failed: {e}")))?;
        Ok(())
    }

    // --- User Keys ---

    pub fn get_user_key(&self, user_id: &Uuid) -> AppResult<Option<StoredKeyEntry>> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT user_id, encrypted_key, created_at, updated_at, last_access_at
                 FROM user_keys WHERE user_id = ?1",
            )
            .map_err(|e| AppError::DatabaseError(format!("Prepare failed: {e}")))?;

        let result = stmt
            .query_row(params![user_id.to_string()], |row| {
                let user_id_str: String = row.get(0)?;
                Ok(StoredKeyEntry {
                    user_id: Uuid::parse_str(&user_id_str)
                        .map_err(|e| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                        })?,
                    encrypted_key: row.get(1)?,
                    created_at: parse_datetime(&row.get::<_, String>(2)?),
                    updated_at: parse_datetime(&row.get::<_, String>(3)?),
                    last_access_at: row.get::<_, Option<String>>(4)?.map(|s| parse_datetime(&s)),
                })
            })
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Query failed: {e}")))?;

        Ok(result)
    }

    pub fn insert_user_key(&self, user_id: &Uuid, encrypted_key: &[u8]) -> AppResult<()> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let now = format_datetime(&Utc::now().naive_utc());
        conn.execute(
            "INSERT INTO user_keys (user_id, encrypted_key, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![user_id.to_string(), encrypted_key, &now, &now],
        )
        .map_err(|e| AppError::DatabaseError(format!("Insert failed: {e}")))?;
        Ok(())
    }

    pub fn update_user_key(&self, user_id: &Uuid, encrypted_key: &[u8]) -> AppResult<()> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let now = format_datetime(&Utc::now().naive_utc());
        let rows = conn
            .execute(
                "UPDATE user_keys SET encrypted_key = ?1, updated_at = ?2 WHERE user_id = ?3",
                params![encrypted_key, &now, user_id.to_string()],
            )
            .map_err(|e| AppError::DatabaseError(format!("Update failed: {e}")))?;

        if rows == 0 {
            return Err(AppError::NotFound(format!("User key not found for {user_id}")));
        }
        Ok(())
    }

    pub fn touch_user_key_access(&self, user_id: &Uuid) -> AppResult<()> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let now = format_datetime(&Utc::now().naive_utc());
        conn.execute(
            "UPDATE user_keys SET last_access_at = ?1 WHERE user_id = ?2",
            params![&now, user_id.to_string()],
        )
        .map_err(|e| AppError::DatabaseError(format!("Touch failed: {e}")))?;
        Ok(())
    }

    pub fn delete_user_key(&self, user_id: &Uuid) -> AppResult<bool> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let rows = conn
            .execute(
                "DELETE FROM user_keys WHERE user_id = ?1",
                params![user_id.to_string()],
            )
            .map_err(|e| AppError::DatabaseError(format!("Delete failed: {e}")))?;
        Ok(rows > 0)
    }

    // --- Bulk operations for secret rotation ---

    /// List all user IDs and their encrypted key blobs.
    /// Used during wrapping secret rotation to re-encrypt every key.
    pub fn get_all_encrypted_keys(&self) -> AppResult<Vec<(Uuid, Vec<u8>)>> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT user_id, encrypted_key FROM user_keys")
            .map_err(|e| AppError::DatabaseError(format!("Prepare failed: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let uid_str: String = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                let user_id = Uuid::parse_str(&uid_str)
                    .map_err(|e| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                    })?;
                Ok((user_id, blob))
            })
            .map_err(|e| AppError::DatabaseError(format!("Query failed: {e}")))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| AppError::DatabaseError(format!("Row read failed: {e}")))?);
        }
        Ok(result)
    }

    /// Atomically replace ALL user key blobs AND the wrapping secret in one transaction.
    /// If any step fails, the entire operation is rolled back — no data is lost.
    pub fn rotate_all_keys_atomic(
        &self,
        re_encrypted_keys: &[(Uuid, Vec<u8>)],
        new_wrapped_secret_b64: &str,
    ) -> AppResult<()> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| AppError::DatabaseError(format!("Begin transaction failed: {e}")))?;

        // Update every user key blob
        for (user_id, new_blob) in re_encrypted_keys {
            let now = format_datetime(&Utc::now().naive_utc());
            let rows = tx
                .execute(
                    "UPDATE user_keys SET encrypted_key = ?1, updated_at = ?2 WHERE user_id = ?3",
                    params![new_blob, &now, user_id.to_string()],
                )
                .map_err(|e| AppError::DatabaseError(format!("Key update failed for {user_id}: {e}")))?;

            if rows == 0 {
                return Err(AppError::DatabaseError(format!(
                    "Rotation integrity error: user {user_id} disappeared mid-rotation"
                )));
            }
        }

        // Update the stored wrapping secret
        tx.execute(
            "INSERT OR REPLACE INTO app_data (key, value) VALUES (?1, ?2)",
            params!["wrapping_secret_enc", new_wrapped_secret_b64],
        )
        .map_err(|e| AppError::DatabaseError(format!("Wrapping secret update failed: {e}")))?;

        // Record rotation timestamp
        let now = format_datetime(&Utc::now().naive_utc());
        tx.execute(
            "INSERT OR REPLACE INTO app_data (key, value) VALUES (?1, ?2)",
            params!["last_rotation_at", &now],
        )
        .map_err(|e| AppError::DatabaseError(format!("Rotation timestamp update failed: {e}")))?;

        tx.commit()
            .map_err(|e| AppError::DatabaseError(format!("Commit failed — NO data was changed: {e}")))?;

        Ok(())
    }

    // --- User Encrypted Key (UK_enc) ---
    // Stores the user's symmetric key encrypted with their master key (UK_enc).
    // This is the `key` field from POST /api/accounts/set-key-connector-key.
    // It is injected into the login response so the Bitwarden client can call
    // GET /user-keys to retrieve the master key and decrypt the vault.

    pub fn get_user_encrypted_key(&self, user_id: &Uuid) -> AppResult<Option<String>> {
        let db_key = format!("user_encrypted_key:{user_id}");
        self.get_app_data(&db_key)
    }

    /// Store UK_enc only if not already present (first enrollment only).
    /// Returns true if stored, false if already existed.
    pub fn set_user_encrypted_key_if_absent(&self, user_id: &Uuid, uk_enc: &str) -> AppResult<bool> {
        let db_key = format!("user_encrypted_key:{user_id}");
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let rows = conn
            .execute(
                "INSERT OR IGNORE INTO app_data (key, value) VALUES (?1, ?2)",
                params![db_key, uk_enc],
            )
            .map_err(|e| AppError::DatabaseError(format!("Insert UK_enc failed: {e}")))?;
        Ok(rows > 0)
    }

    // --- App Data ---

    pub fn get_app_data(&self, key: &str) -> AppResult<Option<String>> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT value FROM app_data WHERE key = ?1")
            .map_err(|e| AppError::DatabaseError(format!("Prepare failed: {e}")))?;

        let result = stmt
            .query_row(params![key], |row| row.get(0))
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Query failed: {e}")))?;

        Ok(result)
    }

    pub fn set_app_data(&self, key: &str, value: &str) -> AppResult<()> {
        let conn = self.conn.lock().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO app_data (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map_err(|e| AppError::DatabaseError(format!("Upsert failed: {e}")))?;
        Ok(())
    }
}

fn format_datetime(dt: &NaiveDateTime) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string()
}

fn parse_datetime(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ"))
        .unwrap_or_else(|_| Utc::now().naive_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> Database {
        Database::open(":memory:").unwrap()
    }

    #[test]
    fn test_insert_and_get_user_key() {
        let db = temp_db();
        let user_id = Uuid::new_v4();
        let key_data = b"encrypted-key-bytes";

        db.insert_user_key(&user_id, key_data).unwrap();
        let record = db.get_user_key(&user_id).unwrap().unwrap();

        assert_eq!(record.user_id, user_id);
        assert_eq!(record.encrypted_key, key_data.to_vec());
        assert!(record.last_access_at.is_none());
    }

    #[test]
    fn test_get_nonexistent_key() {
        let db = temp_db();
        let result = db.get_user_key(&Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_update_user_key() {
        let db = temp_db();
        let user_id = Uuid::new_v4();

        db.insert_user_key(&user_id, b"old-key").unwrap();
        db.update_user_key(&user_id, b"new-key").unwrap();

        let record = db.get_user_key(&user_id).unwrap().unwrap();
        assert_eq!(record.encrypted_key, b"new-key".to_vec());
    }

    #[test]
    fn test_update_nonexistent_returns_error() {
        let db = temp_db();
        let result = db.update_user_key(&Uuid::new_v4(), b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_touch_access() {
        let db = temp_db();
        let user_id = Uuid::new_v4();
        db.insert_user_key(&user_id, b"key").unwrap();

        let before = db.get_user_key(&user_id).unwrap().unwrap();
        assert!(before.last_access_at.is_none());

        db.touch_user_key_access(&user_id).unwrap();

        let after = db.get_user_key(&user_id).unwrap().unwrap();
        assert!(after.last_access_at.is_some());
    }

    #[test]
    fn test_delete_user_key() {
        let db = temp_db();
        let user_id = Uuid::new_v4();
        db.insert_user_key(&user_id, b"key").unwrap();

        assert!(db.delete_user_key(&user_id).unwrap());
        assert!(db.get_user_key(&user_id).unwrap().is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let db = temp_db();
        assert!(!db.delete_user_key(&Uuid::new_v4()).unwrap());
    }

    #[test]
    fn test_duplicate_insert_fails() {
        let db = temp_db();
        let user_id = Uuid::new_v4();
        db.insert_user_key(&user_id, b"key1").unwrap();
        let result = db.insert_user_key(&user_id, b"key2");
        assert!(result.is_err());
    }

    #[test]
    fn test_app_data_roundtrip() {
        let db = temp_db();
        assert!(db.get_app_data("test_key").unwrap().is_none());

        db.set_app_data("test_key", "test_value").unwrap();
        assert_eq!(db.get_app_data("test_key").unwrap().unwrap(), "test_value");

        db.set_app_data("test_key", "updated_value").unwrap();
        assert_eq!(db.get_app_data("test_key").unwrap().unwrap(), "updated_value");
    }
}
