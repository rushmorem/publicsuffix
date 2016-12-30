#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate reqwest;
extern crate idna;

pub mod errors;

#[cfg(test)]
mod tests;

use std::io::Read;
use std::fs::File;
use std::path::Path;
use std::collections::HashMap;

use errors::*;
use reqwest::IntoUrl;
use idna::domain_to_unicode;

#[derive(Debug)]
struct Suffix {
    rule: String,
    typ: Type,
}

#[derive(Debug)]
pub struct List {
    rules: HashMap<String, Vec<Suffix>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Type {
    Icann,
    Private,
}

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

    pub fn from_url<U: IntoUrl>(url: U) -> Result<List> {
        reqwest::get(url)
            .map_err(|err| ErrorKind::Request(err).into())
            .and_then(Self::build)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<List> {
        File::open(path)
            .map_err(|err| ErrorKind::Io(err).into())
            .and_then(Self::build)
    }

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

    pub fn icann(&self) -> Vec<&String> {
        self.find_type(Type::Icann)
    }

    pub fn private(&self) -> Vec<&String> {
        self.find_type(Type::Private)
    }

    pub fn all(&self) -> Vec<&String> {
        self.rules.values()
            .fold(Vec::new(), |mut res, ref suffices| {
                for suffix in *suffices {
                    res.push(&suffix.rule);
                }
                res
            })
    }
}

impl Domain {
    fn is_valid(domain: &str) -> bool {
        match domain {
            d if d.starts_with('.') => { return false; }
            _ => { true }
        }
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

    fn find_match(input: &str, domain: &str, domain_is_valid: bool, candidates: Vec<&Suffix>) -> Result<Domain> {
        let d_labels: Vec<&str> = domain.split('.').rev().collect();

        let mut registrable = None;
        let mut suffix = None;
        let mut typ = None;
        let mut num_labels = 0;

        if domain_is_valid {
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
        }

        Ok(Domain {
            full: input.to_string(),
            typ: typ,
            suffix: suffix,
            registrable: registrable,
        })
    }

    pub fn parse(domain: &str, list: &List) -> Result<Domain> {
        let input = domain;

        let domain = input.trim().trim_right_matches('.');
        let (domain, res) = domain_to_unicode(domain);
        if let Err(errors) = res {
            return Err(ErrorKind::Uts46(errors).into());
        }

        let domain_is_valid = Domain::is_valid(input);

        let res = if domain_is_valid {
            Self::find_possible_matches(&domain, list)?
        } else {
            Vec::new()
        };

        Self::find_match(input, &domain, domain_is_valid, res)
    }

    pub fn root_domain(&self) -> Option<&String> {
        match self.registrable {
            Some(ref registrable) => Some(registrable),
            None => None,
        }
    }

    pub fn suffix(&self) -> Option<&String> {
        match self.suffix {
            Some(ref suffix) => Some(suffix),
            None => None,
        }
    }

    pub fn is_private(&self) -> bool {
        match self.typ {
            Some(typ) => match typ {
                Type::Icann => false,
                Type::Private => true,
            },
            None => false,
        }
    }

    pub fn is_icann(&self) -> bool {
        match self.typ {
            Some(typ) => match typ {
                Type::Icann => true,
                Type::Private => false,
            },
            None => false,
        }
    }
}
