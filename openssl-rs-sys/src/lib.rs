#![allow(
    clippy::missing_safety_doc,
    clippy::unreadable_literal,
    clippy::upper_case_acronyms,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    overflowing_literals,
    unused_imports
)]
#![recursion_limit = "128"] // configure fixed limit across all rust versions

pub use crate::prelude::*;

#[cfg(not(ossl300))]
pub use aes::*;
pub use asn1::*;
pub use bio::*;
pub use bn::*;
pub use cms::*;
pub use conf::*;
pub use crypto::*;
#[cfg(not(ossl300))]
pub use dh::*;
pub use dsa::*;
pub use dtls1::*;
pub use ec::*;
pub use err::*;
pub use evp::*;
pub use hmac::*;
pub use obj_mac::*;
pub use object::*;
pub use ocsp::*;
pub use ossl_typ::*;
pub use pem::*;
pub use pkcs12::*;
pub use pkcs7::*;
pub use rand::*;
pub use rsa::*;
pub use safestack::*;
pub use sha::*;
pub use srtp::*;
pub use ssl::*;
pub use ssl3::*;
pub use stack::*;
pub use tls1::*;
pub use types::*;
pub use x509::*;
pub use x509_vfy::*;
pub use x509v3::*;

#[cfg(ossl300)]
pub use provider::*;

#[macro_use]
mod macros;

#[cfg(not(ossl300))]
mod aes;
mod asn1;
mod bio;
mod bn;
mod cms;
mod conf;
mod crypto;
#[cfg(not(ossl300))]
mod dh;
mod dsa;
mod dtls1;
mod ec;
mod err;
mod evp;
mod hmac;
mod obj_mac;
mod object;
mod ocsp;
mod ossl_typ;
mod pem;
mod pkcs12;
mod pkcs7;
mod rand;
mod rsa;
mod safestack;
mod sha;
mod srtp;
mod ssl;
mod ssl3;
mod stack;
mod tls1;
mod types;
mod x509;
mod x509_vfy;
mod x509v3;

#[cfg(ossl300)]
mod provider;

mod prelude;


mod ossl_init;
pub use ossl_init::*;
