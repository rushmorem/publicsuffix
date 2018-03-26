#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate publicsuffix;

use std::str;

use publicsuffix::List;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = str::from_utf8(data) {
        let list = List::from_path("/tmp/public_suffix_list.dat").unwrap();
        let _ = list.parse_domain(input);
    }
});
