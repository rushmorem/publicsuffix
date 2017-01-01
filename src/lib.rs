//! The Public Suffix List Client Library
//!
//! This library allows you to easily and accurately validate
//! or break down any given domain name.
//!
//! ## Examples
//!
//! ```
//! extern crate publicsuffix;
//!
//! use publicsuffix::List;
//!
//! fn main() {
//!     let list = List::fetch().unwrap();
//!
//!     let domain = list.parse_domain("www.example.com").unwrap();
//!     let tld = domain.root_domain().unwrap();
//!     assert_eq!(tld, &String::from("example.com"));
//!
//!     let domain = list.parse_domain("www.食狮.中国").unwrap();
//!     let tld = domain.root_domain().unwrap();
//!     assert_eq!(tld, &String::from("食狮.中国"));
//!
//!     let domain = list.parse_domain("www.xn--85x722f.xn--55qx5d.cn").unwrap();
//!     let tld = domain.root_domain().unwrap();
//!     assert_eq!(tld, &String::from("xn--85x722f.xn--55qx5d.cn"));
//!
//!     let domain = list.parse_domain("a.b.domain.biz").unwrap();
//!     let suffix = domain.suffix().unwrap();
//!     assert_eq!(suffix, &String::from("biz"));
//!
//!     let domain = list.parse_domain("a.b.example.uk.com").unwrap();
//!     let suffix = domain.suffix().unwrap();
//!     assert_eq!(suffix, &String::from("uk.com"));
//! }

#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate reqwest;
extern crate regex;
extern crate idna;

pub mod errors;

#[cfg(test)]
mod tests;

use std::io::Read;
use std::fs::File;
use std::path::Path;
use std::collections::HashMap;

use errors::*;
use regex::Regex;
use reqwest::IntoUrl;
use idna::{domain_to_unicode, domain_to_ascii};

#[derive(Debug)]
struct Suffix {
    rule: String,
    typ: Type,
}

/// Stores the public suffix list
///
/// You can use the methods, `fetch`, `from_url` or `from_path` to build the list.
/// If you are using this in a long running server it's recommended you use either
/// `fetch` or `from_url` to download updates at least once a week.
#[derive(Debug)]
pub struct List {
    rules: HashMap<String, Vec<Suffix>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Type {
    Icann,
    Private,
}

/// Holds information about a particular domain
///
/// This is created by `Domain::parse` or `List::parse_domain`.
#[derive(Debug, Clone)]
pub struct Domain {
    full: String,
    typ: Option<Type>,
    suffix: Option<String>,
    registrable: Option<String>,
}

const OFFICIAL_URL: &'static str = "https://publicsuffix.org/list/public_suffix_list.dat";

impl List {
    fn append(&mut self, rule: &str, typ: Type) -> Result<()> {
        rule.rsplit('.').next()
            .ok_or(ErrorKind::InvalidRule(rule.into()).into())
            .and_then(|tld| {
                if tld.is_empty() {
                    return Err(ErrorKind::InvalidRule(rule.into()).into());
                }
                Ok(tld)})
            .and_then(|tld| {
                self.rules.entry(tld.into()).or_insert(Vec::new())
                    .push(Suffix {
                        rule: rule.into(),
                        typ: typ,
                    });
                Ok(())
            })
    }

    fn build<R: Read>(mut reader: R) -> Result<List> {
        let mut res = String::new();
        reader.read_to_string(&mut res)?;

        let mut typ = Type::Icann;

        let mut list = List {
            rules: HashMap::new(),
        };

        for line in res.lines() {
            match line {
                line if line.contains("BEGIN ICANN DOMAINS") => { typ = Type::Icann; }
                line if line.contains("BEGIN PRIVATE DOMAINS") => { typ = Type::Private; }
                line if line.starts_with("//") => { continue; }
                line => {
                    let rule = match line.split_whitespace().next() {
                        Some(rule) => rule,
                        None => continue,
                    };
                    list.append(rule, typ)?;
                }
            }
        }

        Ok(list)
    }

    /// Pull the list from a URL
    pub fn from_url<U: IntoUrl>(url: U) -> Result<List> {
        reqwest::get(url)
            .map_err(|err| ErrorKind::Request(err).into())
            .and_then(Self::build)
    }

    /// Fetch the list from a local file
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<List> {
        File::open(path)
            .map_err(|err| ErrorKind::Io(err).into())
            .and_then(Self::build)
    }

    /// Pull the list from the official URL
    pub fn fetch() -> Result<List> {
        Self::from_url(OFFICIAL_URL)
    }

    fn find_type(&self, typ: Type) -> Vec<&String> {
        self.rules.values()
            .fold(Vec::new(), |mut res, ref suffices| {
                for suffix in *suffices {
                    if suffix.typ == typ {
                        res.push(&suffix.rule);
                    }
                }
                res
            })
    }

    /// Gets a list of all ICANN domain suffices
    pub fn icann(&self) -> Vec<&String> {
        self.find_type(Type::Icann)
    }

    /// Gets a list of all private domain suffices
    pub fn private(&self) -> Vec<&String> {
        self.find_type(Type::Private)
    }

    /// Gets a list of all domain suffices
    pub fn all(&self) -> Vec<&String> {
        self.rules.values()
            .fold(Vec::new(), |mut res, ref suffices| {
                for suffix in *suffices {
                    res.push(&suffix.rule);
                }
                res
            })
    }

    /// Parses a domain using the list
    pub fn parse_domain(&self, domain: &str) -> Result<Domain> {
        Domain::parse(domain, self)
    }
}

impl Domain {
    /// Check if a domain has valid syntax
    pub fn has_valid_syntax(domain: &str) -> bool {
        // we are explicitly checking for this here before calling `domain_to_ascii`
        // because `domain_to_ascii` strips of leading dots so we won't be able to
        // check for this later
        if domain.starts_with('.') { return false; }
        // let's convert the domain to ascii early on so we can validate
        // internationalised domain names as well
        let domain = match domain_to_ascii(domain) {
            Ok(domain) => domain,
            Err(_) => { return false; },
        };
        // all labels must conform to this pattern
        let pattern = Regex::new("^([[:alnum:]]+|[[:alnum:]]+[[:alnum:]-]*[[:alnum:]]+)$").unwrap();
        let mut labels: Vec<&str> = domain.split('.').collect();
        // strip of the first dot from a domain to support fully qualified domain names
        if domain.ends_with(".") { labels.pop(); }
        labels.reverse();
        for (i, label) in labels.iter().enumerate() {
            // any label must be 63 characters or less
            if label.chars().count() > 63 { return false; }
            // the tld must not be a number
            if i == 0 && label.parse::<f64>().is_ok() { return false; }
            // any label must only contain allowed characters
            if !pattern.is_match(label) { return false; }
        }
        true
    }

    fn find_possible_matches<'a>(domain: &str, list: &'a List) -> Result<Vec<&'a Suffix>> {
        let tld = match domain.rsplit('.').next() {
            Some(tld) => {
                if tld.is_empty() { return Ok(Vec::new()); }
                tld
            },
            None => { return Ok(Vec::new()); },
        };
        let candidates = match list.rules.get(tld) {
            Some(candidates) => candidates,
            None => { return Ok(Vec::new()); },
        };
        let candidates = candidates.iter()
            .fold(Vec::new(), |mut res, ref suffix| {
                res.push(*suffix);
                res
            });
        Ok(candidates)
    }

    fn assemble(input: &str, s_len: usize) -> String {
        let domain = input.to_lowercase();

        let d_labels: Vec<&str> = domain
            .trim_right_matches('.')
            .split('.').rev().collect();

        (&d_labels[..s_len]).iter().rev()
            .map(|part| *part)
            .collect::<Vec<_>>()
            .join(".")
    }

    fn find_match(input: &str, domain: &str, candidates: Vec<&Suffix>) -> Result<Domain> {
        let d_labels: Vec<&str> = domain.split('.').rev().collect();

        let mut registrable = None;
        let mut suffix = None;
        let mut typ = None;
        let mut num_labels = 0;

        let no_possible_matches_found = candidates.is_empty();

        for candidate in candidates {
            let s_labels: Vec<&str> = candidate.rule.split('.').rev().collect();
            if s_labels.len() > d_labels.len() { continue; }
            for (i, label) in s_labels.iter().enumerate() {
                if *label == d_labels[i] || *label == "*" || label.trim_left_matches('!') == d_labels[i] {
                    if i == s_labels.len()-1 {
                        if s_labels.len() >= num_labels {
                            num_labels = s_labels.len();
                            typ = Some(candidate.typ);
                            let s_len = if label.starts_with("!") {
                                s_labels.len()-1
                            } else {
                                s_labels.len()
                            };
                            suffix = Some(Self::assemble(input, s_len));
                            if d_labels.len() > s_len {
                                registrable = Some(Self::assemble(input, s_len+1));
                            } else {
                                registrable = None;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }

        if suffix.is_none() && d_labels.len() > 1 && no_possible_matches_found {
            suffix = Some(Self::assemble(input, 1));
            registrable = Some(Self::assemble(input, 2));
        }

        Ok(Domain {
            full: input.to_string(),
            typ: typ,
            suffix: suffix,
            registrable: registrable,
        })
    }

    /// Parses a domain using the list
    pub fn parse(domain: &str, list: &List) -> Result<Domain> {
        let input = domain;
        if !Self::has_valid_syntax(input) {
            return Err(ErrorKind::InvalidDomain(input.into()).into());
        }
        let domain = input.trim().trim_right_matches('.');
        let (domain, res) = domain_to_unicode(domain);
        if let Err(errors) = res {
            return Err(ErrorKind::Uts46(errors).into());
        }
        Self::find_possible_matches(&domain, list)
            .and_then(|res| Self::find_match(input, &domain, res))
    }

    /// Gets the root domain portion if any
    pub fn root_domain(&self) -> Option<&String> {
        match self.registrable {
            Some(ref registrable) => Some(registrable),
            None => None,
        }
    }

    /// Gets the suffix if any
    pub fn suffix(&self) -> Option<&String> {
        match self.suffix {
            Some(ref suffix) => Some(suffix),
            None => None,
        }
    }

    /// Whether the domain has a private suffix
    pub fn is_private(&self) -> bool {
        match self.typ {
            Some(typ) => match typ {
                Type::Icann => false,
                Type::Private => true,
            },
            None => false,
        }
    }

    /// Whether the domain has an ICANN suffix
    pub fn is_icann(&self) -> bool {
        match self.typ {
            Some(typ) => match typ {
                Type::Icann => true,
                Type::Private => false,
            },
            None => false,
        }
    }

    /// Whether this domain's suffix is in the list
    ///
    /// If it is, this is definately a valid domain. If it's not
    /// chances are very high that this isn't a valid domain name,
    /// however, it might simply be because the suffix is new and
    /// it hasn't been added to the list yet.
    ///
    /// If you want to validate a domain name, use this as a quick
    /// check but fall back to a DNS lookup if it returns false.
    pub fn has_known_suffix(&self) -> bool {
        self.typ.is_some()
    }
}
