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
                let expected = match test[3] {
                    "None" => None,
                    res => Some(res.to_string()),
                };
                let domain = Domain::parse(input, &list).unwrap();
                let found = match domain.root_domain() {
                    Some(found) => Some(found.to_string()),
                    None => None,
                };
                if expected != found {
                    let msg = format!("Given {}, we expected {:?}, but found {:?} on line {}. The domain is {:?}.", input, expected, found, i+1, domain);
                    panic!(msg);
                }
            }
        }
    }
}
