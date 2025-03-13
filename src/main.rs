use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Arg, Command};
use rpassword::prompt_password;
use zeroize::Zeroize;

// Argon2
use argon2::{Argon2, Algorithm, Version, Params};

// AES-GCM
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};

// Rand for salt/nonce
use rand::{rng, RngCore};

/// Magic header to detect encryption vs. plaintext.
const MAGIC_HEADER: &[u8] = b"MYENCAPP";
const MAGIC_HEADER_LEN: usize = 8;

// Argon2id parameters
const ARGON2_MEMORY_KIB: u32 = 65536;  // 64 MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const DERIVED_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn main() -> Result<()> {
    // Build the CLI but don't run it yet
    let cmd = Command::new("mysecureapp")
        // Remove built-in help/version flags
        .disable_help_flag(true)     
        .disable_version_flag(true)
        // We'll parse with `try_get_matches()` so we can handle errors ourselves
        .arg(
            Arg::new("file")
                .help("File to encrypt or decrypt in-place.")
                .required(true),
        );

    // Attempt to parse CLI arguments
    let matches = match cmd.try_get_matches() {
        Ok(m) => m,
        Err(_) => {
            // If arguments are invalid (e.g., missing <file>),
            // we handle the error ourselves to avoid Clap's default usage/hint.
            eprintln!("Error: No file argument provided.");
            std::process::exit(1);
        }
    };

    let file_path = matches
        .get_one::<String>("file")
        .expect("File is required, but wasn't provided."); // shouldn't happen after above check

    in_place_mode(file_path)
}

/// Determines if we should encrypt or decrypt by magic header, then overwrites the file in-place.
fn in_place_mode(path_str: &str) -> Result<()> {
    let path = Path::new(path_str);
    let data = fs::read(path)
        .with_context(|| format!("Failed to read file '{}'", path.display()))?;

    // Detect whether we encrypt or decrypt
    let mode = detect_mode(&data);
    match mode {
        FileMode::Encrypt => {
            let mut pw1 = prompt_password("Enter password to encrypt: ")?;
            if pw1.is_empty() {
                return Err(anyhow!("Password cannot be empty."));
            }
            let mut pw2 = prompt_password("Confirm password: ")?;
            if pw1 != pw2 {
                pw1.zeroize();
                pw2.zeroize();
                return Err(anyhow!("Passwords do not match. Aborting."));
            }
            pw2.zeroize();

            let ciphertext = encrypt_data(&data, &mut pw1)?;
            atomic_overwrite(path, &ciphertext)?;
            println!("File encrypted in-place: '{}'", path.display());

            pw1.zeroize();
        }
        FileMode::Decrypt => {
            let mut pw = prompt_password("Enter password to decrypt: ")?;
            if pw.is_empty() {
                return Err(anyhow!("Password cannot be empty."));
            }

            let plaintext = decrypt_data(&data, &mut pw)?;
            atomic_overwrite(path, &plaintext)?;
            println!("File decrypted in-place: '{}'", path.display());

            pw.zeroize();
        }
    }

    Ok(())
}

/// Checks if file_data starts with MAGIC_HEADER => decrypt; otherwise encrypt.
fn detect_mode(file_data: &[u8]) -> FileMode {
    if file_data.len() >= MAGIC_HEADER_LEN && &file_data[..MAGIC_HEADER_LEN] == MAGIC_HEADER {
        FileMode::Decrypt
    } else {
        FileMode::Encrypt
    }
}

enum FileMode {
    Encrypt,
    Decrypt,
}

/// Encrypt plaintext => [magic | salt | nonce | ciphertext].
fn encrypt_data(plaintext: &[u8], password: &mut String) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);

    let mut key = derive_key_argon2id(password, &salt)?;

    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Error creating AES-GCM: {:?}", e))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

    // Build output
    let mut out = Vec::with_capacity(MAGIC_HEADER_LEN + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC_HEADER);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    // Zeroize
    key.zeroize();
    salt.zeroize();
    nonce_bytes.zeroize();

    Ok(out)
}

/// Decrypt data => plaintext. Expects [magic | salt | nonce | ciphertext].
fn decrypt_data(file_data: &[u8], password: &mut String) -> Result<Vec<u8>> {
    if file_data.len() < MAGIC_HEADER_LEN + SALT_LEN + NONCE_LEN {
        return Err(anyhow!("File too short to contain header/salt/nonce."));
    }

    let salt_start = MAGIC_HEADER_LEN;
    let salt_end = salt_start + SALT_LEN;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LEN;

    let salt_slice = &file_data[salt_start..salt_end];
    let nonce_slice = &file_data[nonce_start..nonce_end];
    let ciphertext = &file_data[nonce_end..];

    let mut key = derive_key_argon2id(password, salt_slice)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Error creating AES-GCM: {:?}", e))?;

    let nonce = Nonce::from_slice(nonce_slice);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: bad password or corrupted data."))?;

    key.zeroize();

    Ok(plaintext)
}

/// Derive a 32-byte key from (password, salt) via Argon2id.
fn derive_key_argon2id(password: &mut String, salt: &[u8]) -> Result<Vec<u8>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| anyhow!("Argon2 param error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 hash error: {}", e))?;

    Ok(key)
}

/// Atomically overwrite original file with a *.tmp -> rename approach.
fn atomic_overwrite(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Invalid path: no file name."))?;

    let mut tmp_path = PathBuf::from(path);
    tmp_path.set_file_name(format!("{}.tmp", file_name.to_string_lossy()));

    // 1) Write data to temp
    fs::write(&tmp_path, data)
        .with_context(|| format!("Failed to write temporary file '{}'", tmp_path.display()))?;

    // 2) Rename temp -> original
    fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename '{}' -> '{}'", tmp_path.display(), path.display()))?;

    Ok(())
}


