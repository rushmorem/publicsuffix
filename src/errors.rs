//! Errors returned by this library

#[cfg(feature = "remote_list")]
use std::net::TcpStream;

error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Request(::hyper::Error) #[cfg(feature = "remote_list")];
        HttpParse(::hyper::error::ParseError) #[cfg(feature = "remote_list")];
        Tls(::native_tls::Error) #[cfg(feature = "remote_list")];
        Handshake(::native_tls::HandshakeError<TcpStream>) #[cfg(feature = "remote_list")];
    }

    errors {
        UnsupportedScheme { }

        InvalidList { }

        InvalidUrl { }

        InvalidHost { }

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
