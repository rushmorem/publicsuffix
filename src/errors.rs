//! Errors returned by this library

use std::net::TcpStream;

error_chain! {
    foreign_links {
        Request(::hyper::Error);
        Io(::std::io::Error);
        HttpParse(::hyper::error::ParseError);
        Tls(::native_tls::Error);
        Handshake(::native_tls::HandshakeError<TcpStream>);
    }

    errors {
        InvalidList { }

        InvalidUrl { }

        InvalidRule(t: String) {
            description("invalid rule")
            display("invalid rule: '{}'", t)
        }

        InvalidDomain(t: String) {
            description("invalid domain")
            display("invalid domain: '{}'", t)
        }

        Uts46(t: ::idna::uts46::Errors) {
            description("UTS #46 processing failed")
            display("UTS #46 processing error: '{:?}'", t)
        }
    }
}
