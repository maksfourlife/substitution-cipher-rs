use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
    pub cipher_name: CipherName,
}

#[derive(Clone, Subcommand)]
pub enum Command {
    Encrypt,
    Decrypt,
}

#[derive(Clone, ValueEnum)]
pub enum CipherName {
    Affine,
    AffineRecurrent,
    Substitution,
}
