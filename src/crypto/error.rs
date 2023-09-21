use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

pub enum CryptoError {
    GroupNotSpecified,
}

impl CryptoError {
    fn message(&self) -> Cow<'static, str> {
        match self {
            Self::GroupNotSpecified => Cow::Borrowed("Group not specified"),
        }
    }
}

impl Debug for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.message())
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for CryptoError {}
