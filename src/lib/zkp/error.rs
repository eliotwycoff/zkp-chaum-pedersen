use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};
use tonic::Status;

pub enum Error {
    GroupNotSpecified,
}

impl Error {
    fn message(&self) -> Cow<'static, str> {
        match self {
            Self::GroupNotSpecified => Cow::Borrowed("Group not specified"),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.message())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.message())
    }
}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        match error {
            Error::GroupNotSpecified => Self::internal("Group not specified"),
        }
    }
}

impl std::error::Error for Error {}
