//! A native Rust library for Mozilla's Public Suffix List

#![cfg_attr(not(any(feature = "punycode", feature = "std")), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;

use crate::alloc::borrow::ToOwned;
#[cfg(feature = "anycase")]
use alloc::string::String;
#[cfg(not(feature = "anycase"))]
use alloc::vec::Vec;
#[cfg(feature = "anycase")]
use core::str;
use core::str::{from_utf8, FromStr};
use hashbrown::HashMap;
#[cfg(feature = "anycase")]
use unicase::UniCase;

pub use error::Error;
pub use psl_types::{Domain, Info, List as Psl, Suffix, Type};

/// The official URL of the list
pub const LIST_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";

#[cfg(not(feature = "anycase"))]
type Children = HashMap<Vec<u8>, Node>;

#[cfg(feature = "anycase")]
type Children = HashMap<UniCase<String>, Node>;

const WILDCARD: &str = "*";

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct Node {
    children: Children,
    leaf: Option<Leaf>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
struct Leaf {
    is_exception: bool,
    typ: Option<Type>,
}

/// A dynamic public suffix list
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct List(Node);

impl List {
    /// Creates a new list with default wildcard rule support
    pub fn new() -> Self {
        let mut children = Children::new();
        children.insert(
            #[cfg(not(feature = "anycase"))]
            WILDCARD.as_bytes().to_vec(),
            #[cfg(feature = "anycase")]
            UniCase::new(WILDCARD.to_owned()),
            Node {
                leaf: Some(Default::default()),
                ..Default::default()
            },
        );
        Self(Node {
            children,
            ..Default::default()
        })
    }

    /// Creates a new list from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        from_utf8(bytes)
            .map_err(|_| Error::ListNotUtf8Encoded)?
            .parse()
    }

    /// Checks to see if the list is empty, ignoring the wildcard rule
    pub fn is_empty(&self) -> bool {
        self.0.children.len() < 2
    }

    fn append(&mut self, mut rule: &str, typ: Type) -> Result<(), Error> {
        let mut is_exception = false;
        if rule.starts_with('!') {
            if !rule.contains('.') {
                return Err(Error::ExceptionAtFirstLabel(rule.to_owned()));
            }
            is_exception = true;
            rule = &rule[1..];
        }

        let mut current = &mut self.0;
        for label in rule.rsplit('.') {
            if label.is_empty() {
                return Err(Error::EmptyLabel(rule.to_owned()));
            }

            let children = &mut current.children;

            #[cfg(not(feature = "anycase"))]
            let entry = children.entry(label.as_bytes().to_vec());

            #[cfg(feature = "anycase")]
            let entry = children.entry(UniCase::new(label.to_owned()));

            current = entry.or_insert_with(Default::default);
        }

        current.leaf = Some(Leaf {
            is_exception,
            typ: Some(typ),
        });

        Ok(())
    }
}

impl Psl for List {
    #[inline]
    fn find<'a, T>(&self, labels: T) -> Info
    where
        T: Iterator<Item = &'a [u8]>,
    {
        let mut info = Info { len: 0, typ: None };
        let mut len = 0;

        let mut current = &self.0;
        for label in labels {
            let is_first_label = len == 0;
            #[cfg(not(feature = "anycase"))]
            let node_opt = current.children.get(label);
            #[cfg(feature = "anycase")]
            let node_opt = match str::from_utf8(label) {
                Ok(label) => current.children.get(&UniCase::new(label.to_owned())),
                Err(_) => return Info { len: 0, typ: None },
            };
            match node_opt {
                Some(node) => {
                    current = node;
                }
                None => {
                    #[cfg(not(feature = "anycase"))]
                    let node_opt = current.children.get(WILDCARD.as_bytes());
                    #[cfg(feature = "anycase")]
                    let node_opt = current.children.get(&UniCase::new(WILDCARD.to_owned()));
                    match node_opt {
                        Some(node) => {
                            current = node;
                        }
                        None => break,
                    }
                }
            }
            let label_len = label.len();
            len += if is_first_label {
                label_len
            } else {
                1 + label_len
            };
            if let Some(leaf) = current.leaf {
                if leaf.is_exception {
                    len -= 1 + label_len;
                }
                info.len = len;
                info.typ = leaf.typ;
            } else if is_first_label {
                info.len = len;
            }
        }

        info
    }
}

impl FromStr for List {
    type Err = Error;

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
        Ok(list)
    }
}

impl Default for List {
    fn default() -> Self {
        Self::new()
    }
}
