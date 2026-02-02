use keyring::Entry;
use rusqlite::Connection;
use tauri::{Manager, State};
use crate::protocol;
use crate::app_state::DbState;
use std::collections::HashMap;

#[tauri::command]
pub fn store_secret(app: tauri::AppHandle, key: String, value: String) -> Result<(), String> {
    if let Ok(entry) = Entry::new("Entropy", &key) {
        let _ = entry.set_password(&value);
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }
    let secret_path = app_data_dir.join(format!("{}.secret", key));
    std::fs::write(secret_path, value).map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
pub fn get_secret(app: tauri::AppHandle, key: String) -> Result<String, String> {
    if let Ok(entry) = Entry::new("Entropy", &key) {
        if let Ok(pass) = entry.get_password() {
            return Ok(pass);
        }
    }
    
    if let Ok(entry) = Entry::new("io.entropy.messenger", &key) {
        if let Ok(pass) = entry.get_password() {
            return Ok(pass);
        }
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let secret_path = app_data_dir.join(format!("{}.secret", key));
    if secret_path.exists() {
        return std::fs::read_to_string(secret_path).map_err(|e| e.to_string());
    }

    Err("Secret not found".to_string())
}

#[tauri::command]
pub fn init_vault(app: tauri::AppHandle, state: State<'_, DbState>, passphrase: String) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }

    let db_path = app_data_dir.join("vault.db");

    // Close existing connection if any to release file locks
    {
        let mut conn_lock = state.conn.lock().unwrap();
        if let Some(conn) = conn_lock.as_ref() {
            // If already opened and functional, we can just return Ok
            // This handles UI reloads without needing to re-open the file
            if conn.execute("SELECT 1 FROM vault LIMIT 1;", []).is_ok() {
                return Ok(());
            }
        }
        *conn_lock = None;
    }

    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    if let Err(e) = conn.pragma_update(None, "key", passphrase) {
        return Err(format!("Failed to set encryption key: {}", e));
    }

    protocol::init_database(&conn)?;

    let mut db_conn = state.conn.lock().unwrap();
    *db_conn = Some(conn);
    Ok(())
}

#[tauri::command]
pub fn clear_vault(state: State<'_, DbState>) -> Result<(), String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        conn.execute("DELETE FROM vault;", []).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn vault_save(state: State<'_, DbState>, key: String, value: String) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        conn.execute(
            "INSERT OR REPLACE INTO vault (key, value) VALUES (?1, ?2);",
            [key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
pub fn vault_load(state: State<'_, DbState>, key: String) -> Result<Option<String>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn
            .prepare("SELECT value FROM vault WHERE key = ?1;")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([key]).map_err(|e| e.to_string())?;

        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            Ok(Some(row.get(0).map_err(|e| e.to_string())?))
        } else {
            Ok(None)
        }
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
pub fn dump_vault(state: State<'_, DbState>) -> Result<HashMap<String, String>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn.prepare("SELECT key, value FROM vault;").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| e.to_string())?;

        let mut data = HashMap::new();
        for row in rows {
            let (k, v) = row.map_err(|e| e.to_string())?;
            data.insert(k, v);
        }
        Ok(data)
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
pub fn restore_vault(state: State<'_, DbState>, data: HashMap<String, String>) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        for (k, v) in data {
            conn.execute(
                "INSERT OR REPLACE INTO vault (key, value) VALUES (?1, ?2);",
                [&k, &v],
            ).map_err(|e| e.to_string())?;
        }
        Ok(())
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
pub fn nuclear_reset(app: tauri::AppHandle, state: State<'_, DbState>) -> Result<(), String> {
    if let Ok(mut conn) = state.conn.lock() {
        *conn = None;
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let _ = protocol::secure_nuke_database(&app_data_dir.join("vault.db"));
    let _ = protocol::secure_nuke_database(&app_data_dir.join("entropy_vault_salt.secret"));
    let _ = Entry::new("Entropy", "entropy_vault_salt").map(|entry| entry.delete_credential());
    
    Ok(())
}
