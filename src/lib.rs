#![cfg(target_os = "windows")]
#![allow(clippy::missing_safety_doc)]

mod manual_map;

use std::slice;

pub mod codes {
    pub const OK: i32 = 0;
    pub const E_BAD_INPUT: i32 = -1;
    pub const E_OPEN_PROCESS: i32 = -2;
    pub const E_PE_PARSE: i32 = -3;
    pub const E_ALLOC: i32 = -4;
    pub const E_WRITE: i32 = -5;
    pub const E_THREAD: i32 = -7;
    pub const E_REMOTE_RC: i32 = -8;
}

#[no_mangle]
pub unsafe extern "system" fn injector_run(
    pid: u32,
    dll: *const u8,
    dll_len: usize,
    flags: u32,
) -> i32 {
    if dll.is_null() || dll_len < 4096 {
        return codes::E_BAD_INPUT;
    }
    let dll_bytes = slice::from_raw_parts(dll, dll_len);
    match manual_map::inject(pid, dll_bytes, flags) {
        Ok(()) => codes::OK,
        Err(code) => code,
    }
}
