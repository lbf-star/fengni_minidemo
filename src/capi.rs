use std::os::raw::{c_uchar};
use std::ptr;
use crate::dynamic_framing::{SaltGenerator, build_dynamic_frame, DynamicStreamParser, SilentConfig};

/// Opaque handle for SilentConfig
pub struct SilentConfigHandle(SilentConfig);

/// Create a default configuration.
/// The caller must free this with silent_config_destroy.
#[unsafe(no_mangle)]
pub extern "C" fn silent_config_default() -> *mut SilentConfigHandle {
    Box::into_raw(Box::new(SilentConfigHandle(SilentConfig::default())))
}

/// Destroy a configuration handle.
#[unsafe(no_mangle)]
pub extern "C" fn silent_config_destroy(handle: *mut SilentConfigHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Opaque handle for SaltGenerator
pub struct SaltGeneratorHandle(SaltGenerator);

/// Create a diversified salt generator.
/// seed: 32 bytes array
/// stream_id: u64
#[unsafe(no_mangle)]
pub extern "C" fn silent_generator_create(
    seed: *const c_uchar,
    stream_id: u64
) -> *mut SaltGeneratorHandle {
    if seed.is_null() { return ptr::null_mut(); }
    let mut seed_arr = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(seed, seed_arr.as_mut_ptr(), 32); }
    
    Box::into_raw(Box::new(SaltGeneratorHandle(SaltGenerator::new_diversified(seed_arr, stream_id))))
}

/// Destroy a generator handle.
#[unsafe(no_mangle)]
pub extern "C" fn silent_generator_destroy(handle: *mut SaltGeneratorHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Build a dynamic frame (Encryption/Framing).
/// generator: handle
/// input: pointer to input data
/// input_len: length of input data
/// config: handle to config
/// out_buf: pointer to output buffer (caller allocated)
/// out_max_len: size of out_buf
/// out_written: pointer to size_t to receive actual written size
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn silent_build_frame(
    generator: *mut SaltGeneratorHandle,
    input: *const c_uchar,
    input_len: usize,
    config: *const SilentConfigHandle,
    out_buf: *mut c_uchar,
    out_max_len: usize,
    out_written: *mut usize
) -> i32 {
    if generator.is_null() || input.is_null() || config.is_null() || out_buf.is_null() || out_written.is_null() {
        return -1;
    }
    
    let generator_obj = unsafe { &mut (*generator).0 };
    let conf = unsafe { &(*config).0 };
    let input_slice = unsafe { std::slice::from_raw_parts(input, input_len) };
    
    match build_dynamic_frame(generator_obj, input_slice, *conf) {
        Ok(framed) => {
            if framed.len() > out_max_len {
                return -2; // Buffer too small
            }
            unsafe {
                ptr::copy_nonoverlapping(framed.as_ptr(), out_buf, framed.len());
                *out_written = framed.len();
            }
            0
        }
        Err(_) => -3,
    }
}

/// Opaque handle for DynamicStreamParser
pub struct SilentParserHandle(DynamicStreamParser);

/// Create a stream parser.
/// generator: handle (consumed/used for initialization)
#[unsafe(no_mangle)]
pub extern "C" fn silent_parser_create(generator: *mut SaltGeneratorHandle) -> *mut SilentParserHandle {
    if generator.is_null() { return ptr::null_mut(); }
    let generator_obj = unsafe { Box::from_raw(generator).0 };
    Box::into_raw(Box::new(SilentParserHandle(DynamicStreamParser::new(generator_obj))))
}

/// Destroy a parser handle.
#[unsafe(no_mangle)]
pub extern "C" fn silent_parser_destroy(handle: *mut SilentParserHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Append data to the parser buffer.
#[unsafe(no_mangle)]
pub extern "C" fn silent_parser_append(
    handle: *mut SilentParserHandle,
    data: *const c_uchar,
    len: usize
) -> i32 {
    if handle.is_null() || data.is_null() { return -1; }
    let parser = unsafe { &mut (*handle).0 };
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };
    
    match parser.append_data(data_slice) {
        Ok(_) => 0,
        Err(_) => -4,
    }
}

/// Try to parse the next frame from the parser.
/// Returns 1 if a message was parsed, 0 if more data is needed, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn silent_parse_next(
    handle: *mut SilentParserHandle,
    config: *const SilentConfigHandle,
    out_buf: *mut c_uchar,
    out_max_len: usize,
    out_written: *mut usize
) -> i32 {
    if handle.is_null() || config.is_null() || out_buf.is_null() || out_written.is_null() {
        return -1;
    }
    
    let parser = unsafe { &mut (*handle).0 };
    let conf = unsafe { &(*config).0 };
    
    match parser.try_parse_next(*conf) {
        Ok(Some(payload)) => {
            if payload.len() > out_max_len {
                return -2;
            }
            unsafe {
                ptr::copy_nonoverlapping(payload.as_ptr(), out_buf, payload.len());
                *out_written = payload.len();
            }
            1
        }
        Ok(None) => 0,
        Err(_) => -5,
    }
}
