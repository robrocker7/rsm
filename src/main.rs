use std::env;
use rusqlite::{params, Connection, Result};
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use buffer::{BufferResult, ReadBuffer, WriteBuffer};
use std::error::Error;
use clap::{App, Arg, SubCommand};

// Encrypt function
fn encrypt(data: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let data_bytes = data.as_bytes();
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data_bytes);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

// Decrypt function
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<String, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    let decrypted_data_string = String::from_utf8(final_result)
    .map_err(|_| symmetriccipher::SymmetricCipherError::InvalidLength)?;
    Ok(decrypted_data_string)
}

// Store a secret
fn put_secret(conn: &Connection, secret_name: &str, secret_data_json: &str, key: &[u8], iv: &[u8]) -> Result<()> {
    let encrypted_data = encrypt(secret_data_json, key, iv).expect("Encryption failed");

    let insert_result = conn.execute(
        "INSERT INTO secrets (name, data) VALUES (?1, ?2)",
        params![secret_name, encrypted_data],
    );

    if let Err(rusqlite::Error::SqliteFailure(err, _)) = insert_result {
        if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
            // Delete the existing record
            conn.execute("DELETE FROM secrets WHERE name = ?1", params![secret_name])?;

            // Try inserting again
            conn.execute(
                "INSERT INTO secrets (name, data) VALUES (?1, ?2)",
                params![secret_name, encrypted_data],
            )?;

        } else {
            // If the error is not due to a primary key constraint, re-raise it
            return Err(insert_result.unwrap_err());
        }
    }


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

fn main() -> Result<(), Box<dyn Error>> {
    // Your encryption key and IV (must be securely generated and managed)
    let key = env::var("RSM_KEY").unwrap().into_bytes();
    //let key = b"1234567890ABCDEF1234567890ABCDEF"; // 32 bytes for AES-256
    //let iv = b"1234567890ABCDEF"; // 16 bytes for AES
    let iv = env::var("RSM_IV").unwrap().into_bytes();

    let matches = App::new("Secrets Manager")
        .version("1.0")
        .author("Your Name")
        .about("Manages secrets")
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
        .get_matches();
    let mut path = env::current_exe()?;
    path.pop();
    path.push("secrets.db");
    let conn = Connection::open(path)?;

    // Create the table for storing secrets
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            data BLOB NOT NULL
        )",
        [],
    )?;

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
    }
    Ok(())
}