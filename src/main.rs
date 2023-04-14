use std::{
    env,
    io::{self, Stdin},
};

use aes::{
    cipher::{
        block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut,
        BlockSizeUser, Iv, KeyIvInit, KeySizeUser, Unsigned,
    },
    Aes256,
};
use anyhow::Result;
use base64::Engine;
use clap::{
    arg, crate_authors, crate_description, crate_name, crate_version, ArgGroup, ArgMatches, Command,
};
use human_panic::setup_panic;
use rand::{thread_rng, RngCore};

/// fetch parameter from command line argument, environment variable or standard input
fn get_param(id: &str, args: &ArgMatches, prompt: &str, stdin: &Stdin) -> String {
    if let Some(param) = args.get_one::<String>(id) {
        return param.to_string();
    }
    if let Ok(param) = env::var(id.to_uppercase()) {
        return param;
    }
    if !args.get_flag("silent") {
        println!("{prompt}");
    }
    let mut buffer = String::new();
    stdin
        .read_line(&mut buffer)
        .expect("failed to read from stdin");
    buffer.lines().next().unwrap().to_string()
}

fn aes_encrypt(buffer: &[u8], key: &str) -> Vec<u8> {
    let key_raw = key.as_bytes();
    let mut key = GenericArray::from([0; <Aes256 as KeySizeUser>::KeySize::USIZE]);
    key[..key_raw.len()].copy_from_slice(key_raw);
    let mut iv = GenericArray::from([0; <Aes256 as BlockSizeUser>::BlockSize::USIZE]);
    thread_rng().fill_bytes(&mut iv);
    let result = cbc::Encryptor::<Aes256>::new(&key, &iv).encrypt_padded_vec_mut::<Pkcs7>(buffer);
    [iv.to_vec(), result].concat()
}

fn aes_decrypt(buffer: &[u8], key: &str) -> Result<Vec<u8>> {
    let key_raw = key.as_bytes();
    let mut key = GenericArray::from([0; <Aes256 as KeySizeUser>::KeySize::USIZE]);
    key[..key_raw.len()].copy_from_slice(key_raw);
    let iv = Iv::<cbc::Decryptor<Aes256>>::from_slice(
        &buffer[..<Aes256 as BlockSizeUser>::BlockSize::USIZE],
    );
    let result = cbc::Decryptor::<Aes256>::new(&key, &iv)
        .decrypt_padded_vec_mut::<Pkcs7>(&buffer[<Aes256 as BlockSizeUser>::BlockSize::USIZE..])?;
    Ok(result)
}

#[inline]
fn to_base64(buffer: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(buffer)
}

#[inline]
fn from_base64(base64: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(base64)?)
}

fn main() -> Result<()> {
    setup_panic!();
    let args = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(arg!(-k --key <KEY> "Pass key from command line"))
        .arg(arg!(-t --text <TEXT> "Pass text from command line"))
        .arg(arg!(-d --decrypt "Decrypt"))
        .arg(arg!(-s --silent "Do not display prompt"))
        .arg(arg!(-e --eof "End text with EOF rather than new line"))
        .arg(
            arg!(-n --"no-envvar" "Do not attempt to fetch key and text from environment variable"),
        )
        .arg(arg!(-a --"aes-gcm-siv" "Use AES-GCM-SIV cipher"))
        .arg(arg!(-c --chacha20poly1305 "Use ChaCha20Poly1305 cipher"))
        .group(ArgGroup::new("cipher").args(["aes-gcm-siv", "chacha20poly1305"]))
        .after_help("KEY and TEXT may also be passed with environment variable or standard input.")
        .get_matches();
    let stdin = io::stdin();
    let text = get_param("text", &args, "Input your txt:", &stdin);
    let key = get_param("key", &args, "Input your key:", &stdin);
    if !args.get_flag("decrypt") {
        let result = if args.get_flag("aes-gcm-siv") {
            Vec::new()
        } else if args.get_flag("chacha20poly1305") {
            Vec::new()
        } else {
            aes_encrypt(text.as_bytes(), key.as_str())
        };
        println!("{}", to_base64(result.as_slice()));
    } else {
        let text = from_base64(text.as_str())?;
        let result = if args.get_flag("aes-gcm-siv") {
            Vec::new()
        } else if args.get_flag("chacha20poly1305") {
            Vec::new()
        } else {
            aes_decrypt(text.as_slice(), key.as_str())?
        };
        println!("{}", String::from_utf8(result)?);
    }
    Ok(())
}
