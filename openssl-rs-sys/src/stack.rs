use libc::*;


        pub enum OPENSSL_STACK {}



        extern "C" {
            pub fn OPENSSL_sk_num(stack: *const OPENSSL_STACK) -> c_int;
            pub fn OPENSSL_sk_value(stack: *const OPENSSL_STACK, idx: c_int) -> *mut c_void;

            pub fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
            pub fn OPENSSL_sk_free(st: *mut OPENSSL_STACK);
            pub fn OPENSSL_sk_pop_free(
                st: *mut OPENSSL_STACK,
                free: Option<unsafe extern "C" fn(*mut c_void)>,
            );
            pub fn OPENSSL_sk_push(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int;
            pub fn OPENSSL_sk_pop(st: *mut OPENSSL_STACK) -> *mut c_void;
        }

