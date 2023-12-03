use bip39::Mnemonic;
use colored::Colorize;
use ring::hkdf;
use std::io::BufRead;

const KDF_LABEL: &[u8] = b"crypto-wallet-hkdf";
// length of the entropy bytes to derive
const SECRET_LENGTH: usize = 32;

#[derive(Debug)]
pub enum Error {
    ReadingBufferError,
    HexDecodingError,
    HkdfGenericError,
}

#[derive(Debug, Clone, PartialEq)]
struct Secret<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> Secret<SIZE> {
    fn new() -> Self {
        let entropy = [0u8; SIZE];
        Self(entropy)
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }

    fn get(&self) -> &[u8] {
        &self.0
    }
}

impl<const SIZE: usize> hkdf::KeyType for Secret<SIZE> {
    fn len(&self) -> usize {
        SIZE
    }
}

pub struct MnemonicGenerator<const SEED_LENGTH: usize> {
    seed: [u8; SEED_LENGTH],
    raw_passwd: Vec<u8>,
}

impl<const SEED_LENGTH: usize> MnemonicGenerator<SEED_LENGTH> {
    pub fn new(seed: [u8; SEED_LENGTH], raw_passwd: Vec<u8>) -> Self {
        Self { seed, raw_passwd }
    }

    pub fn gen(&mut self) -> Result<Mnemonic, Error> {
        let info = &[KDF_LABEL][..];
        // Construct some salt from password
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &self.raw_passwd);
        // Extract phase
        let prk = salt.extract(&self.seed);
        // 256 bit Entropy for the Mnemonic Generation
        let mut secret = Secret::<SECRET_LENGTH>::new();
        // Expand phase
        let okm = prk
            .expand(info, secret.clone())
            .expect("Length is not too large for expansion");
        // Fill Entropy
        okm.fill(secret.as_mut())
            .map_err(|_| Error::HkdfGenericError)?;

        // Generate a mnemonic from the generated secret
        let mnemonic = Mnemonic::from_entropy(secret.get()).expect("Entropy has a valid length");

        Ok(mnemonic)
    }
}

/// Get some raw hex bytes of a specified length from an input buffer
pub fn input_raw_bytes_from<const LENGTH: usize>(
    buffer: &mut dyn BufRead,
) -> Result<[u8; LENGTH], Error> {
    let input = input_from(buffer)?;

    // Remove "0x" prefix
    let input = if input.starts_with("0x") {
        let cleaned_input = input[2..].to_string();
        Ok(cleaned_input)
    } else {
        Err(Error::HexDecodingError)
    }?;

    let mut raw_bytes = [0u8; LENGTH];
    // Parse hexadecimal input into bytes
    match hex::decode(input) {
        Ok(bytes) => {
            raw_bytes.clone_from_slice(&bytes);
            Ok(raw_bytes)
        }
        Err(_) => Err(Error::HexDecodingError),
    }
}

/// Get some password from an input buffer.
pub fn input_password_from(buffer: &mut dyn BufRead) -> Result<Vec<u8>, Error> {
    let passwd = input_from(buffer)?;
    Ok(passwd.as_bytes().to_vec())
}

/// Get an input string from a buffer - excluding the newline delimeter.
fn input_from(buffer: &mut dyn BufRead) -> Result<String, Error> {
    let mut input = String::new();
    // Read until a new line and pop it from input
    buffer
        .read_line(&mut input)
        .map_err(|_| Error::ReadingBufferError)?;
    input.pop(); // Remove the newline character from the password

    Ok(input)
}

/// Display utility
pub struct Display(());
impl Display {
    pub fn welcome() {
        println!();
        println!("{}", "24-word seed GENERATOR!".bold().bright_blue());
        println!("\x1b[0;33m⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣶⣶⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⠀⠀⣀⣤⣾⣿⡿⠿⠛⠛⠛⠛⠛⠛⠛⠻⢿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⠀⢠⣼⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣷⣄⠀⠀⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⣰⣿⡿⠋⠀⠀⠀⠀⠀⣿⡇⠀⢸⣿⡇⠀⠀⠀⠀⠀⠈⢿⣿⣦⡀⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⣸⣿⡿⠀⠀⠀⠸⠿⣿⣿⣿⡿⠿⠿⣿⣿⣿⣶⣄⠀⠀⠀⠀⢹⣿⣷⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⢠⣿⡿⠁⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠈⣿⣿⣿⠀⠀⠀⠀⠀⢹⣿⣧⠀\x1b[0m");
        println!("\x1b[0;33m⠀⣾⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢀⣠⣿⣿⠟⠀⠀⠀⠀⠀⠈⣿⣿⠀\x1b[0m");
        println!("\x1b[0;33m⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⣿⡿⠿⠿⠿⣿⣿⣥⣄⠀⠀⠀⠀⠀⠀⣿⣿⠀\x1b[0m");
        println!("\x1b[0;33m⠀⢿⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⢻⣿⣿⣧⠀⠀⠀⠀⢀⣿⣿⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠘⣿⣷⡀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⣼⣿⣿⡿⠀⠀⠀⠀⣸⣿⡟⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⢹⣿⣷⡀⠀⠀⢰⣶⣿⣿⣿⣷⣶⣶⣾⣿⣿⠿⠛⠁⠀⠀⠀⣾⣿⡿⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⠀⠹⣿⣷⣄⠀⠀⠀⠀⠀⣿⡇⠀⢸⣿⡇⠀⠀⠀⠀⠀⢀⣾⣿⠟⠁⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⠀⠀⠘⢻⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⡿⠋⠀⠀⠀⠀\x1b[0m");
        println!("\x1b[0;33m⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣷⣶⣤⣤⣤⣤⣤⣤⣴⣾⣿⣿⠟⠋⠀⠀⠀⠀⠀\x1b[0m");
        println!();
        println!("🔐{}", "Welcome!".bold().bright_blue());
        let welcome_message = r#"This tool will generate a secure 24-word mnemonic phrase 
from an input seed of 256 bits and a plain password, providing a safeguard 
for your digital assets. Let's get started! 🌟"#;
        println!("{}\n", welcome_message.bright_white());
    }

    pub fn input_request(value: &str) {
        println!("{}", value.bold().bright_purple());
    }

    pub fn success() {
        println!("{}\n", "Acquired!".bold().bright_green());
    }

    pub fn mnemonic(mnemonic: &str) {
        // Header
        println!(
            r#"
   🌟✨🔑 24-WORD SEED GENERATED! 🔑✨🌟
"#
        );

        // Top border
        println!("╔═══════════════════════════════════════════════════════════════════╗");

        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        let max_word_length = words.iter().map(|word| word.len()).max().unwrap_or(0);

        for chunk in words.chunks(6) {
            let formatted_chunk: Vec<String> = chunk
                .iter()
                .map(|word| {
                    let padding = " ".repeat((max_word_length - word.len()) / 2);
                    format!("{}{}{}", padding, word, padding)
                })
                .collect();
            println!("{:^65}", formatted_chunk.join(" "));
        }

        // Bottom border
        println!("╚═══════════════════════════════════════════════════════════════════╝");
        println!();
    }
}
