# PublicSuffix

A native Rust library for Mozilla's Public Suffix List

[![CI](https://github.com/rushmorem/publicsuffix/actions/workflows/ci.yml/badge.svg)](https://github.com/rushmorem/publicsuffix/actions/workflows/ci.yml)
[![Latest Version](https://img.shields.io/crates/v/publicsuffix.svg)](https://crates.io/crates/publicsuffix)
[![Crates.io downloads](https://img.shields.io/crates/d/publicsuffix)](https://crates.io/crates/publicsuffix)
[![Docs](https://docs.rs/publicsuffix/badge.svg)](https://docs.rs/publicsuffix)
[![Minimum supported Rust version](https://img.shields.io/badge/rustc-1.56.1+-yellow.svg)](https://www.rust-lang.org)
![Maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

This library uses Mozilla's [Public Suffix List](https://publicsuffix.org) to reliably determine the suffix of a domain name. This crate provides a dynamic list that can be updated at runtime. If you need a faster, though static list, please use the [psl](https://crates.io/crates/psl) crate instead.

*NB*: v1 of this crate contained logic to validate domain names and email addresses. Since v2, this functionality was moved to the [addr](https://crates.io/crates/addr) crate. This crate also no longer downloads the list for you.

## Setting Up

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
publicsuffix = "2"
```

## Examples

```rust
use publicsuffix::{Psl, List};

// the official list can be found at
// https://publicsuffix.org/list/public_suffix_list.dat
let list: List = "<-- your public suffix list here -->".parse()?;

let suffix = list.suffix(b"www.example.com")?;
assert_eq!(suffix, "com");
assert_eq!(suffix.typ(), Some(Type::Icann));

let domain = list.domain(b"www.example.com")?;
assert_eq!(domain, "example.com");
assert_eq!(domain.suffix(), "com");

let domain = list.domain("www.食狮.中国".as_bytes())?;
assert_eq!(domain, "食狮.中国");
assert_eq!(domain.suffix(), "中国");

let domain = list.domain(b"www.xn--85x722f.xn--55qx5d.cn")?;
assert_eq!(domain, "xn--85x722f.xn--55qx5d.cn");
assert_eq!(domain.suffix(), "xn--55qx5d.cn");

let domain = list.domain(b"a.b.example.uk.com")?;
assert_eq!(domain, "example.uk.com");
assert_eq!(domain.suffix(), "uk.com");

let domain = list.domain(b"_tcp.example.com.")?;
assert_eq!(domain, "example.com.");
assert_eq!(domain.suffix(), "com.");
```
