use libc::*;

use *;

pub enum OSSL_PROVIDER {}
pub enum OSSL_PARAM {}

extern "C" {
    pub fn OSSL_PROVIDER_set_default_search_path(
        libctx: *mut OSSL_LIB_CTX,
        path: *const c_char,
    ) -> c_int;

    pub fn OSSL_PROVIDER_load(libctx: *mut OSSL_LIB_CTX, name: *const c_char)
        -> *mut OSSL_PROVIDER;
    pub fn OSSL_PROVIDER_try_load(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        retain_fallbacks: c_int,
    ) -> *mut OSSL_PROVIDER;
    pub fn OSSL_PROVIDER_unload(prov: *mut OSSL_PROVIDER) -> c_int;
    pub fn OSSL_PROVIDER_available(libctx: *mut OSSL_LIB_CTX, name: *const c_char) -> c_int;
    pub fn OSSL_PROVIDER_do_all(
        ctx: *mut OSSL_LIB_CTX,
        cb: Option<
            unsafe extern "C" fn(provider: *mut OSSL_PROVIDER, cbdata: *mut c_void) -> c_int,
        >,
        cbdata: *mut c_void,
    ) -> c_int;

    pub fn OSSL_PROVIDER_gettable_params(prov: *const OSSL_PROVIDER) -> *const OSSL_PARAM;
    //int OSSL_PROVIDER_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[]);
    pub fn OSSL_PROVIDER_self_test(prov: *const OSSL_PROVIDER) -> c_int;
}
