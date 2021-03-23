#![feature(test)]

extern crate test;

use publicsuffix::{List, Psl};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use test::Bencher;

lazy_static::lazy_static! {
    static ref LIST: List = {
        let root = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let path = Path::new(&root)
            .join("tests")
            .join("public_suffix_list.dat");
        let mut file = File::open(path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents.parse().unwrap()
    };
}

const DOMAIN: &[u8] = b"www.example.com";

#[bench]
fn bench_find(b: &mut Bencher) {
    b.iter(|| LIST.find(DOMAIN.rsplit(|x| *x == b'.')));
}

#[bench]
fn bench_suffix(b: &mut Bencher) {
    b.iter(|| LIST.suffix(DOMAIN).unwrap());
}

#[bench]
fn bench_domain(b: &mut Bencher) {
    b.iter(|| LIST.domain(DOMAIN).unwrap());
}
