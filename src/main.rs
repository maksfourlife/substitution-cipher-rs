use args::{Args, CipherName, Command};
use cipher::{AffineCipher, Cipher};
use clap::Parser;
use std::{io::stdin, str::FromStr};

use crate::cipher::{AffineRecurrentCipher, SubstitutionCipher};

pub mod args;
pub mod cipher;

fn read_from_str<T>() -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    Ok(T::from_str(&input[..input.len() - 1])?)
}

fn main() -> anyhow::Result<()> {
    let Args {
        command,
        cipher_name,
    } = Args::parse();
    let cipher: Box<dyn Cipher> = match cipher_name {
        CipherName::Substitution => {
            println!("Source alphabet:");
            let alph1: String = read_from_str()?;
            println!("Destination alphabet:");
            let alph2: String = read_from_str()?;
            Box::new(SubstitutionCipher::new(alph1, alph2)?)
        }
        CipherName::Affine => {
            println!("Alphabet:");
            let alph: String = read_from_str()?;
            println!("A:");
            let a: usize = read_from_str()?;
            println!("B:");
            let b: usize = read_from_str()?;
            Box::new(AffineCipher::new(alph, a, b)?)
        }
        CipherName::AffineRecurrent => {
            println!("Alphabet:");
            let alph: String = read_from_str()?;
            println!("A1:");
            let a1: usize = read_from_str()?;
            println!("A2:");
            let a2: usize = read_from_str()?;
            println!("B1:");
            let b1: usize = read_from_str()?;
            println!("B2:");
            let b2: usize = read_from_str()?;
            Box::new(AffineRecurrentCipher::new(alph, a1, a2, b1, b2)?)
        }
    };
    match command {
        Command::Encrypt => {
            println!("Message:");
            let cipher_text =
                String::from_utf8(cipher.encrypt(read_from_str::<String>()?.as_bytes())?)?;
            println!("Cipher text:\n{cipher_text}");
        }
        Command::Decrypt => {
            println!("Cipher text:");
            let message =
                String::from_utf8(cipher.decrypt(read_from_str::<String>()?.as_bytes())?)?;
            println!("Message:\n{message}");
        }
    };
    Ok(())
}
