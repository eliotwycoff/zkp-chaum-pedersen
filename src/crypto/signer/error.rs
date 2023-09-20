use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

pub enum SignerError {
    GroupNotSet,
    InvalidGroup(String),
    InvalidSecret,
}

impl SignerError {
    fn message(&self) -> Cow<'static, str> {
        match self {
            Self::GroupNotSet => Cow::Borrowed("Group not set"),
            Self::InvalidGroup(details) => Cow::Owned(format!("Invalid group => {}", details)),
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
