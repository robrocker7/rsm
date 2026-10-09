use serde_json::Value;
use std::env;
use std::path::PathBuf;
use rusqlite::{params, Connection, Result};
use std::error::Error;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use rand::{Rng};


use aes::{Aes256, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;



type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Encrypt function
fn encrypt(data: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).map_err(|e| e.to_string())?;
    Ok(cipher.encrypt_vec(data.as_bytes()))
}

// Decrypt function
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).map_err(|e| e.to_string())?;
    let decrypted_data = cipher.decrypt_vec(encrypted_data).map_err(|e| e.to_string())?;
    Ok(String::from_utf8(decrypted_data)?)
}

// Store a secret
fn put_secret(conn: &Connection, secret_name: &str, secret_data_json: &str, key: &[u8], iv: &[u8]) -> Result<()> {
    let encrypted_data = encrypt(secret_data_json, key, iv).expect("Encryption failed");

    let _insert_result = conn.execute(
        "INSERT OR REPLACE INTO secrets (name, data) VALUES (?1, ?2)",
        params![secret_name, encrypted_data],
    );
    Ok(())
}

// Retrieve a secret
fn get_secret(conn: &Connection, secret_name: &str, key: &[u8], iv: &[u8]) -> Result<String> {
    let mut stmt = conn.prepare("SELECT data FROM secrets WHERE name = ?1")?;
    let mut rows = stmt.query(params![secret_name])?;

    if let Some(row) = rows.next()? {
        let encrypted_data: Vec<u8> = row.get(0)?;
        let decrypted_data = decrypt(&encrypted_data, key, iv).expect("Decryption failed");
        Ok(decrypted_data)
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}

// Exports all secrets in the db
fn export(conn: &Connection, key: &[u8], iv: &[u8]) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare("SELECT name, data FROM secrets")?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let data: Vec<u8> = row.get(1)?;
        let decrypted_data = match decrypt(&data, key, iv) {
            Ok(value) => value,
            Err(_) => {
                return Ok(serde_json::json!({
                    "name": name,
                    "error": "failed to decrypt",
                }));
            }
        };
        let mut secret_json = serde_json::json!({
            "name": name,
            "data": "",
        });
        if serde_json::from_str::<serde_json::Value>(&decrypted_data).is_ok() {
            let json_data: Value = serde_json::from_str(&decrypted_data).unwrap();
            secret_json["data"] = json_data;
        } else {
            secret_json["data"] = serde_json::Value::String(decrypted_data);
        }
        Ok(secret_json)
    })?;
    let mut secrets = Vec::new();
    for secret in rows {
        secrets.push(secret?);
    }
    Ok(secrets)
}

// Imports a list of secrets from the format the export uses
fn import(conn: &Connection, secrest_json_string: &str, key: &[u8], iv: &[u8]) -> Result<Vec<Value>> {
    let mut responses = Vec::new();
    println!("{:?}", secrest_json_string);
    let json: serde_json::Value = serde_json::from_str(&secrest_json_string).expect("JSON was not well-formatted");
    if let Some(secrets) = json.as_array() {
        for secret in secrets {
            let name = &secret["name"].as_str().unwrap();
            match &secret["data"] {
                Value::Object(_) => {
                    match put_secret(conn, name, &secret["data"].to_string(), key, iv) {
                        Ok(_) => responses.push(serde_json::json!({"success": name})),
                        Err(_)=> responses.push(serde_json::json!({"error": name})),
                    }
                },
                Value::String(_) => {
                    let data = secret["data"].as_str().unwrap();
                    match put_secret(conn, name, data, key, iv) {
                        Ok(_) => responses.push(serde_json::json!({"success": name})),
                        Err(_)=> responses.push(serde_json::json!({"error": name})),
                    }
                }
                _ => println!("It's another type"),
            }
        }
    }
    
    Ok(responses)
}

fn random_alphanumeric(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn get_or_create_env_var(var_name: &str) -> String {
    match env::var(var_name) {
        Ok(value) => value,
        Err(_) => {
            let bitsize = if var_name == "RSM_KEY" { 32 } else { 16 };
            let rand_string = random_alphanumeric(bitsize);
            set_env_var_permanently(var_name, &rand_string).expect("Failed to set environment variable permanently");
            rand_string
        },
    }
}

fn configured_db_path(matches: &ArgMatches) -> Option<&str> {
    if let Some((_, sub_matches)) = matches.subcommand() {
        if let Some(path) = sub_matches.value_of("db") {
            return Some(path);
        }
    }
    matches.value_of("db")
}

fn resolve_db_path(matches: &ArgMatches) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = configured_db_path(matches) {
        Ok(PathBuf::from(path))
    } else {
        let mut path = env::current_exe()?;
        path.pop();
        path.push("secrets.db");
        Ok(path)
    }
}

fn ensure_secrets_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            data BLOB NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn load_secret(conn: &Connection, secret_name: &str, key: &[u8], iv: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut stmt = conn.prepare("SELECT data FROM secrets WHERE name = ?1")?;
    let mut rows = stmt.query(params![secret_name])?;

    if let Some(row) = rows.next()? {
        let encrypted_data: Vec<u8> = row.get(0)?;
        decrypt(&encrypted_data, key, iv)
            .map_err(|err| format!("failed to decrypt {secret_name}: {err}").into())
    } else {
        Err(format!("secret not found: {secret_name}").into())
    }
}

fn parse_secret_names(names: &str) -> Vec<String> {
    names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn share(conn: &Connection, filename: &str, names: &[String], key: &[u8], iv: &[u8]) -> Result<Value, Box<dyn Error>> {
    if names.is_empty() {
        return Err("no secret names provided".into());
    }

    let mut payloads = Vec::with_capacity(names.len());
    for name in names {
        payloads.push((name.clone(), load_secret(conn, name, key, iv)?));
    }

    let dest = PathBuf::from(filename);
    if dest.exists() {
        return Err(format!("database already exists: {}", dest.display()).into());
    }

    let new_key = random_alphanumeric(32);
    let new_iv = random_alphanumeric(16);

    let write_result: Result<(), Box<dyn Error>> = (|| {
        let dest_conn = Connection::open(&dest)?;
        ensure_secrets_table(&dest_conn)?;
        for (name, plain) in &payloads {
            put_secret(&dest_conn, name, plain, new_key.as_bytes(), new_iv.as_bytes())?;
        }
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&dest);
        return Err(err);
    }

    Ok(serde_json::json!({
        "filename": filename,
        "RSM_KEY": new_key,
        "RSM_IV": new_iv,
        "secrets": names,
    }))
}

#[cfg(target_os = "windows")]
fn set_env_var_permanently(var_name: &str, value: &str) -> Result<(), std::io::Error> {
    // Not Tested yet
    Command::new("setx")
        .arg(var_name)
        .arg(value)
        .output()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_env_var_permanently(var_name: &str, value: &str) -> Result<(), std::io::Error> {
    let home_dir = env::var("HOME").map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME variable not found"))?;
    println!("{}", home_dir);
    let profile_path = format!("{}/.bashrc", home_dir);
    println!("{}", profile_path);

    let mut current_contents = String::new();
    if fs::metadata(&profile_path).is_ok() {
        fs::File::open(&profile_path)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "Failed to open profile file"))?
            .read_to_string(&mut current_contents)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "Failed to read profile file"))?;
    }

    // Check if the variable assignment already exists
    if current_contents.contains(&format!("export {}=", var_name)) {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
            format!("{} is already defined in {}. Please launch the script in a new terminal session after ensuring {} is not already set or manually remove the existing entry.",
                var_name, profile_path.to_string(), var_name)));
    }

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(profile_path)?;
    writeln!(file, "export {}={}", var_name, value)?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let key = get_or_create_env_var("RSM_KEY").into_bytes();
    let iv = get_or_create_env_var("RSM_IV").into_bytes();

    let matches = App::new("Secrets Manager")
        .version("1.1")
        .author("Robert Johnson")
        .about("Manages secrets")
        .arg(Arg::with_name("db")
            .long("db")
            .env("RSM_DB")
            .global(true)
            .takes_value(true)
            .help("SQLite database path (default: secrets.db next to the rsm binary)"))
        .subcommand(SubCommand::with_name("put")
            .about("Stores a secret")
            .arg(Arg::with_name("name")
                .help("The name of the secret")
                .required(true)
                .index(1))
            .arg(Arg::with_name("value")
                .help("The JSON value of the secret")
                .required(true)
                .index(2)))
        .subcommand(SubCommand::with_name("get")
            .about("Retrieves a secret")
            .arg(Arg::with_name("name")
                .help("The name of the secret")
                .required(true)
                .index(1)))
        .subcommand(SubCommand::with_name("export")
            .about("Exports all secrets to JSON"))
        .subcommand(SubCommand::with_name("import")
            .about("Retrieves a secret")
            .arg(Arg::with_name("data")
                .help("The json data of the secrets")
                .required(true)
                .index(1)))
        .subcommand(SubCommand::with_name("share")
            .about("Export selected secrets into a new database with new encryption keys")
            .arg(Arg::with_name("filename")
                .help("Path of the new database to create")
                .required(true)
                .index(1))
            .arg(Arg::with_name("names")
                .help("Comma-separated secret names to copy")
                .required(true)
                .index(2)))
        .get_matches();

    let path = resolve_db_path(&matches)?;
    {
        let conn = Connection::open(path)?;
        ensure_secrets_table(&conn)?;

        if let Some(matches) = matches.subcommand_matches("put") {
            let name = matches.value_of("name").unwrap();
            let value = matches.value_of("value").unwrap();
            put_secret(&conn, name, value, &key, &iv)?;
            println!("{{\"success\":\"{}\"}}", name);
        } else if let Some(matches) = matches.subcommand_matches("get") {
            let name = matches.value_of("name").unwrap();
            match get_secret(&conn, name, &key, &iv) {
                Ok(secret) => println!("{}", secret),
                Err(e) => println!("Error retrieving secret: {:?}", e),
            }
        } else if let Some(_matches) = matches.subcommand_matches("export") { 
            match export(&conn, &key, &iv) {
                Ok(secrets) => println!("{}", serde_json::json!(secrets).to_string()),
                Err(e) => println!("Error retrieving secret: {:?}", e),
            }
        } else if let Some(matches) = matches.subcommand_matches("import") { 
            let data = matches.value_of("data").unwrap();
            match import(&conn, data, &key, &iv) {
                Ok(secrets) => println!("{}", serde_json::json!(secrets).to_string()),
                Err(e) => println!("Error retrieving secret: {:?}", e),
            }
        } else if let Some(share_matches) = matches.subcommand_matches("share") {
            let filename = share_matches.value_of("filename").unwrap();
            let names = parse_secret_names(share_matches.value_of("names").unwrap());
            let result = share(&conn, filename, &names, &key, &iv)?;
            println!("{}", result);
        }
    }
    Ok(())
}
