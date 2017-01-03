//! Robust domain name parsing using the Public Suffix List
//!
//! This library allows you to easily and accurately parse any given domain name.
//!
//! ## Examples
//!
//! ```rust,norun
//! extern crate publicsuffix;
//!
//! use publicsuffix::List;
//! # use publicsuffix::Result;
//!
//! # fn examples() -> Result<()> {
//! // Fetch the list from the official URL,
//! # #[cfg(feature = "remote_list")]
//! let list = List::fetch()?;
//!
//! // from your own URL
//! # #[cfg(feature = "remote_list")]
//! let list = List::from_url("https://example.com/path/to/public_suffix_list.dat")?;
//!
//! // or from a local file.
//! let list = List::from_path("/path/to/public_suffix_list.dat")?;
//!
//! // Using the list you can find out the root domain
//! // or extension of any given domain name
//! let domain = list.parse_domain("www.example.com")?;
//! assert_eq!(domain.root(), Some("example.com"));
//! assert_eq!(domain.suffix(), Some("com"));
//!
//! let domain = list.parse_domain("www.食狮.中国")?;
//! assert_eq!(domain.root(), Some("食狮.中国"));
//! assert_eq!(domain.suffix(), Some("中国"));
//!
//! let domain = list.parse_domain("www.xn--85x722f.xn--55qx5d.cn")?;
//! assert_eq!(domain.root(), Some("xn--85x722f.xn--55qx5d.cn"));
//! assert_eq!(domain.suffix(), Some("xn--55qx5d.cn"));
//!
//! let domain = list.parse_domain("a.b.example.uk.com")?;
//! assert_eq!(domain.root(), Some("example.uk.com"));
//! assert_eq!(domain.suffix(), Some("uk.com"));
//!
//! // You can also find out if this is an ICANN domain
//! assert!(!domain.is_icann());
//!
//! // or a private one
//! assert!(domain.is_private());
//!
//! // In any case if the domain's suffix is in the list
//! // then this is definately a registrable domain name
//! assert!(domain.has_known_suffix());
//! # Ok(())
//! # }
//! # fn main() {}
//! ```

#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
#[cfg(feature = "remote_list")]
extern crate native_tls;
#[cfg(feature = "remote_list")]
extern crate hyper;
extern crate regex;
extern crate idna;

pub mod errors;

#[cfg(feature = "remote_list")]
#[cfg(test)]
mod tests;

use std::fs::File;
use std::path::Path;
#[cfg(feature = "remote_list")]
use std::time::Duration;
#[cfg(feature = "remote_list")]
use std::net::TcpStream;
use std::io::Read;
#[cfg(feature = "remote_list")]
use std::io::Write;
use std::collections::HashMap;

pub use errors::{Result, Error};

use regex::Regex;
use errors::ErrorKind;
#[cfg(feature = "remote_list")]
use hyper::client::IntoUrl;
#[cfg(feature = "remote_list")]
use native_tls::TlsConnector;
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
/// This is created by `List::parse_domain`.
#[derive(Debug, Clone)]
pub struct Domain {
    full: String,
    typ: Option<Type>,
    suffix: Option<String>,
    registrable: Option<String>,
}

#[cfg(feature = "remote_list")]
fn request<U: IntoUrl>(u: U) -> Result<String> {
    let url = u.into_url()?;
    let addr = url.with_default_port(|_| Err(()))?;
    let host = match url.host_str() {
        Some(host) => host,
        None => { return Err(ErrorKind::InvalidUrl.into()); }
    };
    let data = format!("GET {} HTTP/1.0\r\nHost: {}\r\n\r\n", url.path(), host);
    let stream = TcpStream::connect(addr)?;
    let timeout = Duration::from_secs(2);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut res = String::new();

    if url.scheme() == "https" {
        let connector = TlsConnector::builder()?.build()?;
        let mut stream = connector.connect(host, stream)?;
        stream.write_all(data.as_bytes())?;
        stream.read_to_string(&mut res)?;
    } else {
        let mut stream = stream;
        stream.write_all(data.as_bytes())?;
        stream.read_to_string(&mut res)?;
    }
    Ok(res)
}

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

    fn build(res: String) -> Result<List> {
        let mut typ = None;
        let mut list = List {
            rules: HashMap::new(),
        };
        for line in res.lines() {
            match line {
                line if line.contains("BEGIN ICANN DOMAINS") => { typ = Some(Type::Icann); }
                line if line.contains("BEGIN PRIVATE DOMAINS") => { typ = Some(Type::Private); }
                line if line.starts_with("//") => { continue; }
                line => {
                    match typ {
                        Some(typ) => {
                            let rule = match line.split_whitespace().next() {
                                Some(rule) => rule,
                                None => continue,
                            };
                            list.append(rule, typ)?;
                        }
                        None => { continue; }
                    }
                }
            }
        }
        if list.rules.is_empty() || list.icann().is_empty() || list.private().is_empty() {
            return Err(ErrorKind::InvalidList.into());
        }
        Ok(list)
    }

    /// Pull the list from a URL
    #[cfg(feature = "remote_list")]
    pub fn from_url<U: IntoUrl>(url: U) -> Result<List> {
        request(url).and_then(Self::build)
    }

    /// Fetch the list from a local file
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<List> {
        File::open(path)
            .map_err(|err| ErrorKind::Io(err).into())
            .and_then(|mut data| {
                let mut res = String::new();
                data.read_to_string(&mut res)?;
                Ok(res)
            })
            .and_then(Self::build)
    }

    /// Build the list from the result of anything that implements `std::io::Read`
    ///
    /// If you don't already have your list on the filesystem but want to use your
    /// own library to fetch the list you can use this method so you don't have to
    /// save it first.
    pub fn from_reader<R: Read>(mut reader: R) -> Result<List> {
        let mut res = String::new();
        reader.read_to_string(&mut res)?;
        Self::build(res)
    }

    /// Pull the list from the official URL
    #[cfg(feature = "remote_list")]
    pub fn fetch() -> Result<List> {
        let official = "https://publicsuffix.org/list/public_suffix_list.dat";
        let github = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat";

        Self::from_url(official)
            .or_else(|_| Self::from_url(github))
    }

    fn find_type(&self, typ: Type) -> Vec<&str> {
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
    pub fn icann(&self) -> Vec<&str> {
        self.find_type(Type::Icann)
    }

    /// Gets a list of all private domain suffices
    pub fn private(&self) -> Vec<&str> {
        self.find_type(Type::Private)
    }

    /// Gets a list of all domain suffices
    pub fn all(&self) -> Vec<&str> {
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
    // https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
    // http://blog.sacaluta.com/2011/12/dns-domain-names-253-or-255-bytesoctets.html
    // https://blogs.msdn.microsoft.com/oldnewthing/20120412-00/?p=7873/
    pub fn has_valid_syntax(domain: &str) -> bool {
        // we are explicitly checking for this here before calling `domain_to_ascii`
        // because `domain_to_ascii` strips of leading dots so we won't be able to
        // check for this later
        if domain.starts_with('.') { return false; }
        // let's convert the domain to ascii early on so we can validate
        // internationalised domain names as well
        let domain = match Self::to_ascii(domain) {
            Ok(domain) => {
                let mut len = domain.chars().count();
                if domain.ends_with(".") { len -= 1; }
                if len > 253 { return false; }
                domain
            }
            Err(_) => { return false; }
        };
        // all labels must conform to this pattern
        let pattern = Regex::new("^([[:alnum:]]+|[[:alnum:]]+[[:alnum:]-]*[[:alnum:]]+)$").unwrap();
        let mut labels: Vec<&str> = domain.split('.').collect();
        // strip of the first dot from a domain to support fully qualified domain names
        if domain.ends_with(".") { labels.pop(); }
        // a domain must not have more than 127 labels
        if labels.len() > 127 { return false; }
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
                                let root = Self::assemble(input, s_len+1);
                                registrable = Some(root);
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

    fn to_ascii(domain: &str) -> Result<String> {
        match domain_to_ascii(domain) {
            Ok(domain) => Ok(domain.into()),
            Err(_) => {
                return Err(ErrorKind::InvalidDomain(domain.into()).into());
            },
        }
    }

    fn parse(domain: &str, list: &List) -> Result<Domain> {
        if !Self::has_valid_syntax(domain) {
            return Err(ErrorKind::InvalidDomain(domain.into()).into());
        }
        let input = domain;
        let domain = input.trim().trim_right_matches('.');
        let (domain, res) = domain_to_unicode(domain);
        if let Err(errors) = res {
            return Err(ErrorKind::Uts46(errors).into());
        }
        Self::find_possible_matches(&domain, list)
            .and_then(|res| Self::find_match(input, &domain, res))
    }

    /// Gets the root domain portion if any
    pub fn root(&self) -> Option<&str> {
        match self.registrable {
            Some(ref registrable) => Some(registrable),
            None => None,
        }
    }

    /// Gets the suffix if any
    pub fn suffix(&self) -> Option<&str> {
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
