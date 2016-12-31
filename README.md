# A client library for the Public Suffix List written in Rust

[![Build Status](https://travis-ci.org/rushmorem/publicsuffix.svg?branch=master)](https://travis-ci.org/rushmorem/publicsuffix) [![Latest Version](https://img.shields.io/crates/v/publicsuffix.svg)](https://crates.io/crates/publicsuffix) [![Docs](https://docs.rs/publicsuffix/badge.svg)](https://docs.rs/publicsuffix)

This library allows you to utilise the [Public Suffix List](https://publicsuffix.org) using [Rust](https://www.rust-lang.org).

## OpenSSL

One of the libraries that we depend on depends on [rust-openssl](https://github.com/sfackler/rust-openssl). Make sure that your environment is configured as per their [build instructions](https://github.com/sfackler/rust-openssl#building) before you try to compile anything that depends on this library.
