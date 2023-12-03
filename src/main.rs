use crate::mnemonic::MnemonicGenerator;
use mnemonic::Display;

mod mnemonic;

fn main() {
    Display::welcome();
    // Prepare the stdin buffer
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    // Input a secret 256 bit key
    Display::input_request("Input a hex secret key of 256 bit:");
    let raw_secret =
        mnemonic::input_raw_bytes_from::<32>(&mut handle).expect("Error reading hex bytes");
    Display::success();
    // Input a Password
    Display::input_request("Input your Password:");
    let passwd = mnemonic::input_password_from(&mut handle).expect("Error reading password");
    Display::success();

    // Construct the Generator
    let mut generator = MnemonicGenerator::new(raw_secret, passwd);
    let mnemonic = generator
        .gen()
        .expect("Some error occured while generating the mnemonic phrase");

    // Display the generated mnemonic phrase
    Display::mnemonic(&mnemonic.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_mnemonic_generation() {
        // Mocking user input
        let testing_input = "0x86de0e5ac7ac1a152441818443dfbb5a4600abcf7430f2f70a61507e7078926c\nP4ssw0rd_F0r_Dumm1es\n".as_bytes();
        let mut buffer = io::BufReader::new(testing_input);

        let testing_seed = mnemonic::input_raw_bytes_from::<32>(&mut buffer).unwrap();
        let dummy_passwd = mnemonic::input_password_from(&mut buffer).unwrap();

        let mut generator = MnemonicGenerator::new(testing_seed, dummy_passwd);
        let mnemonic = generator.gen();

        assert!(mnemonic.is_ok())
    }
}
