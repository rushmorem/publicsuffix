//! A native Rust library for Mozilla's Public Suffix List

#![cfg_attr(not(any(feature = "punycode", feature = "std")), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;

#[cfg(feature = "anycase")]
use alloc::borrow::Cow;
use alloc::borrow::ToOwned;
#[cfg(not(any(feature = "hashbrown", feature = "punycode", feature = "std")))]
use alloc::collections::BTreeMap as Map;
#[cfg(not(feature = "anycase"))]
use alloc::vec::Vec;
use core::str::{from_utf8, FromStr};
#[cfg(feature = "hashbrown")]
use hashbrown::HashMap as Map;
#[cfg(all(not(feature = "hashbrown"), any(feature = "punycode", feature = "std")))]
use std::collections::HashMap as Map;
#[cfg(feature = "anycase")]
use unicase::UniCase;

pub use error::Error;
pub use psl_types::{Domain, Info, List as Psl, Suffix, Type};

/// The official URL of the list
pub const LIST_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";

#[cfg(not(feature = "anycase"))]
type Children = Map<Vec<u8>, Node>;

#[cfg(feature = "anycase")]
type Children = Map<UniCase<Cow<'static, str>>, Node>;

const WILDCARD: &str = "*";

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct Node {
    children: Children,
    leaf: Option<Leaf>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Leaf {
    is_exception: bool,
    typ: Type,
}

/// A dynamic public suffix list
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct List {
    rules: Node,
    typ: Option<Type>,
}

impl List {
    /// Creates a new list with default wildcard rule support
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new list from a byte slice
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the list is not UTF-8 encoded
    /// or if its format is invalid.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        from_utf8(bytes)
            .map_err(|_| Error::ListNotUtf8Encoded)?
            .parse()
    }

    /// Checks to see if the list is empty, ignoring the wildcard rule
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.children.is_empty()
    }

    #[inline]
    fn append(&mut self, mut rule: &str, typ: Type) -> Result<(), Error> {
        let mut is_exception = false;
        if rule.starts_with('!') {
            if !rule.contains('.') {
                return Err(Error::ExceptionAtFirstLabel(rule.to_owned()));
            }
            is_exception = true;
            rule = &rule[1..];
        }

        let mut current = &mut self.rules;
        for label in rule.rsplit('.') {
            if label.is_empty() {
                return Err(Error::EmptyLabel(rule.to_owned()));
            }

            #[cfg(not(feature = "anycase"))]
            let key = label.as_bytes().to_owned();
            #[cfg(feature = "anycase")]
            let key = UniCase::new(Cow::from(label.to_owned()));

            current = current.children.entry(key).or_insert_with(Default::default);
        }

        current.leaf = Some(Leaf { is_exception, typ });

        Ok(())
    }
}

#[cfg(feature = "anycase")]
macro_rules! anycase_key {
    ($label:ident) => {
        match from_utf8($label) {
            Ok(label) => UniCase::new(Cow::from(label)),
            Err(_) => return Info { len: 0, typ: None },
        }
    };
}

impl Psl for List {
    #[inline]
    fn find<'a, T>(&self, mut labels: T) -> Info
    where
        T: Iterator<Item = &'a [u8]>,
    {
        let mut rules = &self.rules;

        // the first label
        // it's special because we always need it whether or not
        // it's in our hash map (because of the implicit wildcard)
        let mut info = match labels.next() {
            Some(label) => {
                let mut info = Info {
                    len: label.len(),
                    typ: None,
                };
                #[cfg(not(feature = "anycase"))]
                let node_opt = rules.children.get(label);
                #[cfg(feature = "anycase")]
                let node_opt = rules.children.get(&anycase_key!(label));
                match node_opt {
                    Some(node) => {
                        info.typ = node.leaf.map(|leaf| leaf.typ);
                        rules = node;
                    }
                    None => return info,
                }
                info
            }
            None => return Info { len: 0, typ: None },
        };

        // the rest of the labels
        let mut len_so_far = info.len;
        for label in labels {
            #[cfg(not(feature = "anycase"))]
            let node_opt = rules.children.get(label);
            #[cfg(feature = "anycase")]
            let node_opt = rules.children.get(&anycase_key!(label));
            match node_opt {
                Some(node) => rules = node,
                None => {
                    #[cfg(not(feature = "anycase"))]
                    let node_opt = rules.children.get(WILDCARD.as_bytes());
                    #[cfg(feature = "anycase")]
                    let node_opt = rules.children.get(&UniCase::new(Cow::from(WILDCARD)));
                    match node_opt {
                        Some(node) => rules = node,
                        None => break,
                    }
                }
            }
            let label_plus_dot = label.len() + 1;
            if let Some(leaf) = rules.leaf {
                if self.typ.is_none() || self.typ == Some(leaf.typ) {
                    info.typ = Some(leaf.typ);
                    if leaf.is_exception {
                        info.len = len_so_far;
                        break;
                    }
                    info.len = len_so_far + label_plus_dot;
                }
            }
            len_so_far += label_plus_dot;
        }

        info
    }
}

impl FromStr for List {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut typ = None;
        let mut list = List::new();
        for line in s.lines() {
            match line {
                line if line.contains("BEGIN ICANN DOMAINS") => {
                    typ = Some(Type::Icann);
                }
                line if line.contains("BEGIN PRIVATE DOMAINS") => {
                    typ = Some(Type::Private);
                }
                line if line.starts_with("//") => {
                    continue;
                }
                line => match typ {
                    Some(typ) => {
                        let rule = match line.split_whitespace().next() {
                            Some(rule) => rule,
                            None => continue,
                        };
                        list.append(rule, typ)?;
                        #[cfg(feature = "punycode")]
                        {
                            let ascii = idna::domain_to_ascii(rule)
                                .map_err(|_| Error::InvalidRule(rule.to_owned()))?;
                            list.append(&ascii, typ)?;
                        }
                    }
                    None => {
                        continue;
                    }
                },
            }
        }
        if list.is_empty() {
            return Err(Error::InvalidList);
        }
        Ok(list)
    }
}

/// A list of only ICANN suffixes
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct IcannList(List);

impl From<List> for IcannList {
    #[inline]
    fn from(mut list: List) -> Self {
        list.typ = Some(Type::Icann);
        Self(list)
    }
}

impl From<IcannList> for List {
    #[inline]
    fn from(IcannList(mut list): IcannList) -> Self {
        list.typ = None;
        list
    }
}

impl IcannList {
    /// Creates a new list from a byte slice
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the list is not UTF-8 encoded
    /// or if its format is invalid.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let list = List::from_bytes(bytes)?;
        Ok(list.into())
    }

    /// Checks to see if the list is empty, ignoring the wildcard rule
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for IcannList {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let list = List::from_str(s)?;
        Ok(list.into())
    }
}

impl Psl for IcannList {
    #[inline]
    fn find<'a, T>(&self, labels: T) -> Info
    where
        T: Iterator<Item = &'a [u8]>,
    {
        self.0.find(labels)
    }
}

/// A list of only private suffixes
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PrivateList(List);

impl From<List> for PrivateList {
    #[inline]
    fn from(mut list: List) -> Self {
        list.typ = Some(Type::Private);
        Self(list)
    }
}

impl From<PrivateList> for List {
    #[inline]
    fn from(PrivateList(mut list): PrivateList) -> Self {
        list.typ = None;
        list
    }
}

impl PrivateList {
    /// Creates a new list from a byte slice
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the list is not UTF-8 encoded
    /// or if its format is invalid.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let list = List::from_bytes(bytes)?;
        Ok(list.into())
    }

    /// Checks to see if the list is empty, ignoring the wildcard rule
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for PrivateList {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let list = List::from_str(s)?;
        Ok(list.into())
    }
}

impl Psl for PrivateList {
    #[inline]
    fn find<'a, T>(&self, labels: T) -> Info
    where
        T: Iterator<Item = &'a [u8]>,
    {
        self.0.find(labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &[u8] = b"
        // BEGIN ICANN DOMAINS
        com.uk
        ";

    #[test]
    fn list_construction() {
        let list = List::from_bytes(LIST).unwrap();
        let expected = List {
            typ: None,
            rules: Node {
                children: {
                    let mut children = Children::default();
                    children.insert(
                        #[cfg(not(feature = "anycase"))]
                        b"uk".to_vec(),
                        #[cfg(feature = "anycase")]
                        UniCase::new(Cow::from("uk")),
                        Node {
                            children: {
                                let mut children = Children::default();
                                children.insert(
                                    #[cfg(not(feature = "anycase"))]
                                    b"com".to_vec(),
                                    #[cfg(feature = "anycase")]
                                    UniCase::new(Cow::from("com")),
                                    Node {
                                        children: Default::default(),
                                        leaf: Some(Leaf {
                                            is_exception: false,
                                            typ: Type::Icann,
                                        }),
                                    },
                                );
                                children
                            },
                            leaf: None,
                        },
                    );
                    children
                },
                leaf: None,
            },
        };
        assert_eq!(list, expected);
    }

    #[test]
    fn find_localhost() {
        let list = List::from_bytes(LIST).unwrap();
        let labels = b"localhost".rsplit(|x| *x == b'.');
        assert_eq!(list.find(labels), Info { len: 9, typ: None });
    }

    #[test]
    fn find_uk() {
        let list = List::from_bytes(LIST).unwrap();
        let labels = b"uk".rsplit(|x| *x == b'.');
        assert_eq!(list.find(labels), Info { len: 2, typ: None });
    }

    #[test]
    fn find_com_uk() {
        let list = List::from_bytes(LIST).unwrap();
        let labels = b"com.uk".rsplit(|x| *x == b'.');
        assert_eq!(
            list.find(labels),
            Info {
                len: 6,
                typ: Some(Type::Icann)
            }
        );
    }

    #[test]
    fn find_ide_kyoto_jp() {
        let list = List::from_bytes(b"// BEGIN ICANN DOMAINS\nide.kyoto.jp").unwrap();
        let labels = b"ide.kyoto.jp".rsplit(|x| *x == b'.');
        assert_eq!(
            list.find(labels),
            Info {
                len: 12,
                typ: Some(Type::Icann)
            }
        );
    }
}
