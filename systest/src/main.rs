#![allow(bad_style, clippy::all)]

use libc::*;
use openssl_rs_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
