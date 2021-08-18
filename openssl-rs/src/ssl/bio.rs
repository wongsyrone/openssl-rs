use cfg_if::cfg_if;
use ffi::{
    self, BIO_clear_retry_flags, BIO_new, BIO_set_retry_read, BIO_set_retry_write, BIO,
    BIO_CTRL_DGRAM_QUERY_MTU, BIO_CTRL_FLUSH,
};
#[cfg(ossl111)]
use libc::size_t;
use libc::{c_char, c_int, c_long, c_void, strlen};
use std::any::Any;
use std::io;
use std::io::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use crate::cvt_p;
use crate::error::ErrorStack;

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<dyn Any + Send>>,
    pub dtls_mtu_size: c_long,
}

/// Safe wrapper for BIO_METHOD
pub struct BioMethod(BIO_METHOD);

impl BioMethod {
    fn new<S: Read + Write>() -> Result<BioMethod, ErrorStack> {
        BIO_METHOD::new::<S>().map(BioMethod)
    }
}

unsafe impl Sync for BioMethod {}
unsafe impl Send for BioMethod {}

pub fn new<S: Read + Write>(stream: S) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let method = BioMethod::new::<S>()?;

    let state = Box::new(StreamState {
        stream,
        error: None,
        panic: None,
        dtls_mtu_size: 0,
    });

    unsafe {
        let bio = cvt_p(BIO_new(method.0.get()))?;
        BIO_set_data(bio, Box::into_raw(state) as *mut _);
        BIO_set_init(bio, 1);

        Ok((bio, method))
    }
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    let state = state::<S>(bio);
    state.error.take()
}

pub unsafe fn take_panic<S>(bio: *mut BIO) -> Option<Box<dyn Any + Send>> {
    let state = state::<S>(bio);
    state.panic.take()
}

pub unsafe fn get_ref<'a, S: 'a>(bio: *mut BIO) -> &'a S {
    let state = &*(BIO_get_data(bio) as *const StreamState<S>);
    &state.stream
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    &mut state(bio).stream
}

pub unsafe fn set_dtls_mtu_size<S>(bio: *mut BIO, mtu_size: usize) {
    if mtu_size as u64 > c_long::max_value() as u64 {
        panic!(
            "Given MTU size {} can't be represented in a positive `c_long` range",
            mtu_size
        )
    }
    state::<S>(bio).dtls_mtu_size = mtu_size as c_long;
}

unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    &mut *(BIO_get_data(bio) as *mut _)
}

#[cfg(not(ossl111))]
unsafe extern "C" fn bwrite_old<S: Write>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let state = state::<S>(bio);
    let buf = slice::from_raw_parts(buf as *const _, len as usize);

    match catch_unwind(AssertUnwindSafe(|| state.stream.write(buf))) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_write(bio);
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

#[cfg(ossl111)]
const VEC_CHUNK_SIZE: usize = 2048;
#[cfg(ossl111)]
unsafe extern "C" fn bwrite_ex<S: Write>(
    bio: *mut BIO,
    buf: *const c_char,
    blen: size_t,
    written: *mut size_t,
) -> c_int {
    assert!(!buf.is_null());
    BIO_clear_retry_flags(bio);
    let state = state::<S>(bio);
    let buf = slice::from_raw_parts(buf as *const _, blen as usize);
    // empty write as success
    if buf.is_empty() {
        return 1;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        if Write::is_write_vectored(&state.stream) {
            // vectored IO
            // init with 0
            *written = 0;
            let mut slices = buf
                .chunks(VEC_CHUNK_SIZE)
                .map(io::IoSlice::new)
                .collect::<Vec<_>>();
            let part = &mut slices[..];
            let n = match Write::write_vectored(&mut state.stream, part) {
                Ok(n) => n,
                Err(e) => {
                    return Err(e);
                }
            };
            *written += n;
            Ok(())
        } else {
            // non-vectored IO
            match Write::write(&mut state.stream, buf) {
                Ok(n) if n > 0 => {
                    *written = n;
                    Ok(())
                }
                Ok(n) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("written {} bytes", n),
                )),
                Err(e) => Err(e),
            }
        }
    })) {
        Ok(r) => match r {
            Ok(_) => 1,
            Err(err) => {
                if retriable_error(&err) {
                    BIO_set_retry_write(bio);
                }
                state.error = Some(err);
                0
            }
        },
        Err(err) => {
            state.panic = Some(err);
            0
        }
    }
}

#[cfg(not(ossl111))]
unsafe extern "C" fn bread_old<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let state = state::<S>(bio);
    let buf = slice::from_raw_parts_mut(buf as *mut _, len as usize);

    match catch_unwind(AssertUnwindSafe(|| state.stream.read(buf))) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_read(bio);
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

#[cfg(ossl111)]
unsafe extern "C" fn bread_ex<S: Read>(
    bio: *mut BIO,
    buf: *mut c_char,
    blen: size_t,
    readbytes: *mut size_t,
) -> c_int {
    assert!(!buf.is_null());
    BIO_clear_retry_flags(bio);
    let state = state::<S>(bio);
    let buf = slice::from_raw_parts_mut(buf as *mut _, blen as usize);
    // empty read as success
    if buf.is_empty() {
        return 1;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        if Read::is_read_vectored(&state.stream) {
            // vectored IO
            // init with 0
            *readbytes = 0;
            let mut slices = buf
                .chunks_mut(VEC_CHUNK_SIZE)
                .map(io::IoSliceMut::new)
                .collect::<Vec<_>>();
            let part = &mut slices[..];
            let n = match Read::read_vectored(&mut state.stream, part) {
                Ok(n) => n,
                Err(e) => {
                    return Err(e);
                }
            };
            *readbytes += n;
            Ok(())
        } else {
            // non-vectored IO
            match Read::read(&mut state.stream, buf) {
                Ok(n) if n > 0 => {
                    *readbytes = n;
                    Ok(())
                }
                Ok(n) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("read {} bytes", n),
                )),
                Err(e) => Err(e),
            }
        }
    })) {
        Ok(r) => match r {
            Ok(_) => 1,
            Err(err) => {
                if retriable_error(&err) {
                    BIO_set_retry_read(bio);
                }
                state.error = Some(err);
                0
            }
        },
        Err(err) => {
            state.panic = Some(err);
            0
        }
    }
}

#[allow(clippy::match_like_matches_macro)] // matches macro requires rust 1.42.0
fn retriable_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected => true,
        _ => false,
    }
}

unsafe extern "C" fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    cfg_if! {
        if #[cfg(ossl111)] {
            let orig_len = strlen(s);
            let mut written: size_t = 0;
            let written_handle: *mut _ = &mut written as *mut _;
            let ret = bwrite_ex::<S>(bio, s, orig_len, written_handle);
            if ret == 1 {
                assert!(written as usize == orig_len);
                written as c_int
            } else {
                // fail
                -1
            }
        } else {
            bwrite_old::<S>(bio, s, strlen(s) as c_int)
        }
    }
}

unsafe extern "C" fn ctrl<S: Write>(
    bio: *mut BIO,
    cmd: c_int,
    _num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    let state = state::<S>(bio);

    if cmd == BIO_CTRL_FLUSH {
        match catch_unwind(AssertUnwindSafe(|| state.stream.flush())) {
            Ok(Ok(())) => 1,
            Ok(Err(err)) => {
                state.error = Some(err);
                0
            }
            Err(err) => {
                state.panic = Some(err);
                0
            }
        }
    } else if cmd == BIO_CTRL_DGRAM_QUERY_MTU {
        state.dtls_mtu_size
    } else {
        0
    }
}

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    BIO_set_init(bio, 0);
    BIO_set_num(bio, 0);
    BIO_set_data(bio, ptr::null_mut());
    BIO_set_flags(bio, 0);
    1
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let data = BIO_get_data(bio);
    assert!(!data.is_null());
    Box::<StreamState<S>>::from_raw(data as *mut _);
    BIO_set_data(bio, ptr::null_mut());
    BIO_set_init(bio, 0);
    1
}

cfg_if! {
    if #[cfg(ossl111)] {
        use ffi::{BIO_get_data, BIO_set_data, BIO_set_flags, BIO_set_init};
        use crate::cvt;

        #[allow(bad_style)]
        unsafe fn BIO_set_num(_bio: *mut ffi::BIO, _num: c_int) {}

        #[allow(bad_style, clippy::upper_case_acronyms)]
        struct BIO_METHOD(*mut ffi::BIO_METHOD);

        impl BIO_METHOD {
            fn new<S: Read + Write>() -> Result<BIO_METHOD, ErrorStack> {
                unsafe {
                    let ptr = cvt_p(ffi::BIO_meth_new(ffi::BIO_TYPE_NONE, b"rust\0".as_ptr() as *const _))?;
                    let method = BIO_METHOD(ptr);
                    cvt(ffi::BIO_meth_set_write_ex(method.0, Some(bwrite_ex::<S>)))?;
                    cvt(ffi::BIO_meth_set_read_ex(method.0, Some(bread_ex::<S>)))?;
                    cvt(ffi::BIO_meth_set_puts(method.0, bputs::<S>))?;
                    cvt(ffi::BIO_meth_set_ctrl(method.0, ctrl::<S>))?;
                    cvt(ffi::BIO_meth_set_create(method.0, create))?;
                    cvt(ffi::BIO_meth_set_destroy(method.0, destroy::<S>))?;
                    Ok(method)
                }
            }

            fn get(&self) -> *mut ffi::BIO_METHOD {
                self.0
            }
        }

        impl Drop for BIO_METHOD {
            fn drop(&mut self) {
                unsafe {
                    ffi::BIO_meth_free(self.0);
                }
            }
        }
    } else if #[cfg(any(ossl110, libressl273))] {
        use ffi::{BIO_get_data, BIO_set_data, BIO_set_flags, BIO_set_init};
        use crate::cvt;

        #[allow(bad_style)]
        unsafe fn BIO_set_num(_bio: *mut ffi::BIO, _num: c_int) {}

        #[allow(bad_style, clippy::upper_case_acronyms)]
        struct BIO_METHOD(*mut ffi::BIO_METHOD);

        impl BIO_METHOD {
            fn new<S: Read + Write>() -> Result<BIO_METHOD, ErrorStack> {
                unsafe {
                    let ptr = cvt_p(ffi::BIO_meth_new(ffi::BIO_TYPE_NONE, b"rust\0".as_ptr() as *const _))?;
                    let method = BIO_METHOD(ptr);
                    cvt(ffi::BIO_meth_set_write(method.0, bwrite_old::<S>))?;
                    cvt(ffi::BIO_meth_set_read(method.0, bread_old::<S>))?;
                    cvt(ffi::BIO_meth_set_puts(method.0, bputs::<S>))?;
                    cvt(ffi::BIO_meth_set_ctrl(method.0, ctrl::<S>))?;
                    cvt(ffi::BIO_meth_set_create(method.0, create))?;
                    cvt(ffi::BIO_meth_set_destroy(method.0, destroy::<S>))?;
                    Ok(method)
                }
            }

            fn get(&self) -> *mut ffi::BIO_METHOD {
                self.0
            }
        }

        impl Drop for BIO_METHOD {
            fn drop(&mut self) {
                unsafe {
                    ffi::BIO_meth_free(self.0);
                }
            }
        }
    } else {
        #[allow(bad_style, clippy::upper_case_acronyms)]
        struct BIO_METHOD(*mut ffi::BIO_METHOD);

        impl BIO_METHOD {
            fn new<S: Read + Write>() -> Result<BIO_METHOD, ErrorStack> {
                let ptr = Box::new(ffi::BIO_METHOD {
                    type_: ffi::BIO_TYPE_NONE,
                    name: b"rust\0".as_ptr() as *const _,
                    bwrite: Some(bwrite_old::<S>),
                    bread: Some(bread_old::<S>),
                    bputs: Some(bputs::<S>),
                    bgets: None,
                    ctrl: Some(ctrl::<S>),
                    create: Some(create),
                    destroy: Some(destroy::<S>),
                    callback_ctrl: None,
                });

                Ok(BIO_METHOD(Box::into_raw(ptr)))
            }

            fn get(&self) -> *mut ffi::BIO_METHOD {
                self.0
            }
        }

        impl Drop for BIO_METHOD {
            fn drop(&mut self) {
                unsafe {
                    Box::<ffi::BIO_METHOD>::from_raw(self.0);
                }
            }
        }

        #[allow(bad_style)]
        unsafe fn BIO_set_init(bio: *mut ffi::BIO, init: c_int) {
            (*bio).init = init;
        }

        #[allow(bad_style)]
        unsafe fn BIO_set_flags(bio: *mut ffi::BIO, flags: c_int) {
            (*bio).flags = flags;
        }

        #[allow(bad_style)]
        unsafe fn BIO_get_data(bio: *mut ffi::BIO) -> *mut c_void {
            (*bio).ptr
        }

        #[allow(bad_style)]
        unsafe fn BIO_set_data(bio: *mut ffi::BIO, data: *mut c_void) {
            (*bio).ptr = data;
        }

        #[allow(bad_style)]
        unsafe fn BIO_set_num(bio: *mut ffi::BIO, num: c_int) {
            (*bio).num = num;
        }
    }
}
