

pub fn init() {
    use std::ptr;
    use std::sync::Once;

    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505
    static INIT: Once = Once::new();

    #[cfg(not(ossl111b))]
    let init_options = OPENSSL_INIT_LOAD_SSL_STRINGS;
    #[cfg(ossl111b)]
    let init_options = OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_NO_ATEXIT;

    INIT.call_once(|| unsafe {
        OPENSSL_init_ssl(init_options, ptr::null_mut());
    })
}