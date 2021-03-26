use alloc::string::String;
use core::fmt;

/// Errors returned by this crate
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    EmptyLabel(String),
    ExceptionAtFirstLabel(String),
    InvalidList,
    InvalidRule(String),
    ListNotUtf8Encoded,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::EmptyLabel(rule) => write!(f, "rule `{}` contains an empty label", rule),
            Error::ExceptionAtFirstLabel(rule) => {
                write!(f, "`{}`; exceptions only valid at end of rule", rule)
            }
            Error::InvalidList => write!(f, "the provided list is not valid"),
            Error::InvalidRule(rule) => write!(f, "rule `{}` is invalid", rule),
            Error::ListNotUtf8Encoded => write!(f, "the provided list is not UTF8 encoded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
