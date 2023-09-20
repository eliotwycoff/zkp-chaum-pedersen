use num_bigint::BigUint;
use std::{ borrow::Cow, fmt::{ Debug, Display, Formatter, Result as FmtResult } };

pub enum SignerError {
    GeneratorsNotSet,
    ModuliNotSet,
    InvalidGenerators((BigUint, BigUint)),
    InvalidModuli((BigUint, BigUint)),
    InvalidSecret,
}

impl SignerError {
    fn message(&self) -> Cow<'static, str> {
        match self {
            Self::GeneratorsNotSet => Cow::Borrowed("Generators not set"),
            Self::ModuliNotSet => Cow::Borrowed("Moduli not set"),
            Self::InvalidGenerators((alpha, beta)) =>
                Cow::Owned(format!("Invalid generators (alpha, beta) => ({}, {})", alpha, beta)),
            Self::InvalidModuli((p, q)) =>
                Cow::Owned(format!("Invalid moduli (p, q) => ({}, {})", p, q)),
            Self::InvalidSecret => Cow::Borrowed("Invalid secret"),
        }
    }
}

impl Debug for SignerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.message())
    }
}

impl Display for SignerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for SignerError {}
