use alloc::string::String;
use core::hash::{Hash, Hasher};
use unicase::UniCase;

#[derive(Debug, Clone, Eq)]
pub(super) enum AnyCase<'a> {
    Owned(UniCase<String>),
    Borrowed(UniCase<&'a str>),
}

impl From<String> for AnyCase<'_> {
    fn from(s: String) -> Self {
        Self::Owned(UniCase::new(s))
    }
}

impl<'a> From<&'a str> for AnyCase<'a> {
    fn from(s: &'a str) -> Self {
        Self::Borrowed(UniCase::new(s))
    }
}

impl PartialEq for AnyCase<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match self {
            AnyCase::Owned(this) => match other {
                AnyCase::Owned(other) => this == other,
                AnyCase::Borrowed(other) => this == other,
            },
            AnyCase::Borrowed(this) => match other {
                AnyCase::Owned(other) => this == other,
                AnyCase::Borrowed(other) => this == other,
            },
        }
    }
}

impl Hash for AnyCase<'_> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            AnyCase::Owned(unicase) => unicase.hash(state),
            AnyCase::Borrowed(unicase) => unicase.hash(state),
        }
    }
}
