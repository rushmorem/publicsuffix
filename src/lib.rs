#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate reqwest;
extern crate idna;

pub mod errors;

#[cfg(test)]
mod tests;

use std::io::Read;
use std::collections::HashMap;

use errors::*;
use reqwest::IntoUrl;
use idna::domain_to_ascii;

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
}

impl List {
    fn build(res: String) -> Result<List> {
        let mut typ = Type::Icann;

        let mut list = List {
            rules: HashMap::new(),
        };

        for line in res.lines() {
            match line {
                line if line.contains("BEGIN ICANN DOMAINS") => { typ = Type::Icann; }
                line if line.contains("BEGIN PRIVATE DOMAINS") => { typ = Type::Private; }
                line if line.starts_with("//") => {/* skip comment */}
                line => {
                    let rule = line.trim();
                    if rule.is_empty() {
                        continue;
                    }
                    let tld = rule.rsplit('.').next()
                        .ok_or(ErrorKind::InvalidRule(rule.into()))
                        .and_then(|tld| {
                            if tld.is_empty() {
                                return Err(ErrorKind::InvalidRule(rule.into()));
                            }
                            Ok(tld)
                        })?;
                    list.rules.entry(tld.into()).or_insert(Vec::new())
                        .push(Suffix {
                            rule: rule.into(),
                            typ: typ,
                        });
                }
            }
        }

        list.rules.shrink_to_fit();
        Ok(list)
    }

    pub fn from_url<T: IntoUrl>(url: T) -> Result<List> {
        reqwest::get(url)
            .map_err(|err| ErrorKind::Request(err).into())
            .and_then(|mut res| {
                let mut buf = String::new();
                res.read_to_string(&mut buf)
                    .map_err(|err| ErrorKind::Io(err).into())
                    .and_then(|_| Ok(buf))})
            .and_then(Self::build)
    }

    pub fn from_path(_path: &str) -> Result<List> {
        unimplemented!();
    }

    pub fn fetch() -> Result<List> {
        Self::from_url("https://publicsuffix.org/list/public_suffix_list.dat")
    }

    /*
    fn find_type(&self, typ: Type) -> Vec<&String> {
        self.rules.iter()
            .filter(|&(_, &v)| v == typ)
            .map(|(ref k, _)| *k)
            .collect()
    }

    pub fn icann(&self) -> Vec<&String> {
        self.find_type(Type::Icann)
    }

    pub fn private(&self) -> Vec<&String> {
        self.find_type(Type::Private)
    }

    pub fn all(&self) -> Vec<&String> {
        self.rules.keys().collect()
    }
    */
}

impl Domain {
    pub fn parse<T: Into<String>>(domain: T) -> Domain {
        let _domain = domain.into();
        unimplemented!();
    }

    pub fn suffix(&self) -> Option<String> {
        unimplemented!();
    }

    pub fn is_private(&self) -> bool {
        unimplemented!();
    }

    pub fn is_icann(&self) -> bool {
        unimplemented!();
    }
}
