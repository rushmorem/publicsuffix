# A Rust library for robust domain name parsing

[![Build Status](https://travis-ci.org/rushmorem/publicsuffix.svg?branch=master)](https://travis-ci.org/rushmorem/publicsuffix) [![Latest Version](https://img.shields.io/crates/v/publicsuffix.svg)](https://crates.io/crates/publicsuffix) [![Docs](https://docs.rs/publicsuffix/badge.svg)](https://docs.rs/publicsuffix)

This library uses Mozilla's [Public Suffix List](https://publicsuffix.org) to reliably parse domain names in [Rust](https://www.rust-lang.org). Though parsing domain names is it's primary goal, it also fully exposes the list allowing you to use convenient methods like `list.all()` to get all known domain extensions or `list.icann()` to get only ICANN extensions.

If all you need is to check whether a domain is syntactically correct and do not need to utilise the list you can just use `Domain::has_valid_syntax` method. This method will reliably tell you if a domain has valid syntax whether or not it is an internationalised domain name (IDN). It also checks the length restrictions for each label, total number of labels and full length of domain name.

## Setting Up

Add this crate to your `Cargo.toml`:

```toml
[dependencies.publicsuffix]
version = "1.0"

# This crate exposes the methods `List::fetch` and `List::from_url` as a
# feature named "remote_list". This feature is on by default. If you have
# the public suffix list on your local filesystem or you would like
# to fetch this list on your own you can disable this feature and build
# the list using `List::from_path` or `List::from_reader` respectively.
#
# To disable, uncomment the line below:
# default-features = false
```

## Examples

```rust
extern crate publicsuffix;

use publicsuffix::List;

// Fetch the list from the official URL,
let list = List::fetch()?;

// from your own URL
let list = List::from_url("https://example.com/path/to/public_suffix_list.dat")?;

// or from a local file. You can download the list from
// "https://publicsuffix.org/list/public_suffix_list.dat".
let list = List::from_path("/path/to/public_suffix_list.dat")?;

// Using the list you can find out the root domain
// or extension of any given domain name
let domain = list.parse_domain("www.example.com")?;
assert_eq!(domain.root(), Some("example.com"));
assert_eq!(domain.suffix(), Some("com"));

let domain = list.parse_domain("www.食狮.中国")?;
assert_eq!(domain.root(), Some("食狮.中国"));
assert_eq!(domain.suffix(), Some("中国"));

let domain = list.parse_domain("www.xn--85x722f.xn--55qx5d.cn")?;
assert_eq!(domain.root(), Some("xn--85x722f.xn--55qx5d.cn"));
assert_eq!(domain.suffix(), Some("xn--55qx5d.cn"));

let domain = list.parse_domain("a.b.example.uk.com")?;
assert_eq!(domain.root(), Some("example.uk.com"));
assert_eq!(domain.suffix(), Some("uk.com"));

// You can also find out if this is an ICANN domain
assert!(!domain.is_icann());

// or a private one
assert!(domain.is_private());

// In any case if the domain's suffix is in the list
// then this is definately a registrable domain name
assert!(domain.has_known_suffix());
```
