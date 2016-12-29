error_chain! {
    foreign_links {
        Request(::reqwest::Error);
        Io(::std::io::Error);
    }

    errors {
        InvalidRule(t: String) {
            description("invalid rule")
            display("invalid rule: '{}'", t)
        }
    }
}
