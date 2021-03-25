#![feature(test)]

extern crate test;

use publicsuffix::{List, Psl};
use test::Bencher;

lazy_static::lazy_static! {
    static ref LIST: List = include_str!("../tests/public_suffix_list.dat").parse().unwrap();
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
