//! Shared utility functions for UTF-16 string conversion and FFI helpers.

/// Maximum number of UTF-16 code units to scan when reading a wide string pointer.
const MAX_WIDE_STRING_LEN: usize = 4096;

/// Convert a `usize` length to `u32` for FFI structs.
///
/// WebAuthn response struct fields use `u32` for lengths. All values passed
/// through this function are inherently small (credential IDs are UUIDs at
/// 36 bytes, auth data ~37-140 bytes, signatures ~72 bytes), so truncation
/// is impossible in practice. Using `try_from` instead of `as` makes this
/// guarantee explicit.
pub fn len_as_u32(len: usize) -> u32 {
    u32::try_from(len).expect("length exceeds u32::MAX")
}

/// Create a null-terminated UTF-16 string from a Rust `&str`.
pub fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert a wide (UTF-16) null-terminated pointer to an `Option<String>`.
///
/// Returns `None` if the pointer is null or the string is not valid UTF-16.
/// Scans up to [`MAX_WIDE_STRING_LEN`] code units for the null terminator.
///
/// # Safety
///
/// The pointer must either be null or point to valid memory containing a
/// null-terminated UTF-16 string.
pub unsafe fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while len < MAX_WIDE_STRING_LEN && *ptr.add(len) != 0 {
        len += 1;
    }
    if len == MAX_WIDE_STRING_LEN {
        tracing::warn!("wide string exceeded maximum scan length, truncating");
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16(slice).ok()
}

/// Create a `PCWSTR` for use in Win32 API calls.
///
/// The returned `PCWSTR` borrows from the provided `Vec<u16>`, which must
/// be kept alive for the duration of the call.
pub fn pcwstr(wide: &[u16]) -> windows::core::PCWSTR {
    windows::core::PCWSTR(wide.as_ptr())
}
