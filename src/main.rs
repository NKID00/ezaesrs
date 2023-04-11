use clap::{Command, arg, crate_authors, crate_version, crate_name, crate_description};
use human_panic::setup_panic;

fn main() {
    setup_panic!();
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(arg!(-k --key <KEY> "Pass key from command line"))
        .arg(arg!(-t --text <TEXT> "Pass text from command line"))
        .arg(arg!(-d --decrypt "Decrypt"))
        .arg(arg!(-s --silent "Do not display prompt"))
        .arg(arg!(-a --"aes-gcm-siv" "Use AES-GCM-SIV cipher"))
        .arg(arg!(-c --chacha20poly1305 "Use ChaCha20Poly1305 cipher"))
        .get_matches();
    
}
