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

        Uts46(t: ::idna::uts46::Errors) {
            description("UTS #46 processing failed")
            display("UTS #46 processing error: '{:?}'", t)
        }
    }
}
