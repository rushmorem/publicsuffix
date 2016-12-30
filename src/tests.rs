use std::io::Read;

use {List, Domain, reqwest};

#[test]
fn test_psl() {
    let mut resp = reqwest::get("https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt").unwrap();
    let mut body = String::new();
    resp.read_to_string(&mut body).unwrap();
    let list = List::fetch().unwrap();
    
    for (i, line) in body.lines().enumerate() {
        match line {
            line if line.starts_with("//") => { continue; }
            line => {
                let test = line.trim();
                if test.is_empty() {
                    continue;
                }
                let test = test.replace("null", "'None'");
                let test: Vec<&str> = test.split("'").collect();
                let input = match test[1] {
                    "None" => "",
                    res => res,
                };
                let (expected_root, expected_suffix) = match test[3] {
                    "None" => (None, None),
                    root => {
                        let suffix = {
                            let parts: Vec<&str> = root.split('.').rev().collect();
                            (&parts[..parts.len()-1]).iter().rev()
                                .map(|part| *part)
                                .collect::<Vec<_>>()
                                .join(".")
                        };
                        (Some(root.to_string()), Some(suffix.to_string()))
                    },
                };
                let domain = Domain::parse(input, &list).unwrap();
                let found_root = match domain.root_domain() {
                    Some(found) => Some(found.to_string()),
                    None => None,
                };
                let found_suffix = match domain.suffix() {
                    Some(found) => Some(found.to_string()),
                    None => None,
                };
                if expected_root != found_root || (expected_root.is_some() && expected_suffix != found_suffix) {
                    let msg = format!("\n\nGiven '{}':\nWe expected root domain to be '{:?}' and suffix be '{:?}'\nBut instead, we have '{:?}' as root domain and '{:?}' as suffix.\nWe are on line {} of `test_psl.txt`.\n\n",
                                      input, expected_root, expected_suffix, found_root, found_suffix, i+1);
                    panic!(msg);
                }
            }
        }
    }
}
