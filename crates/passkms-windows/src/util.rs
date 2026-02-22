//! Shared utility functions for UTF-16 string conversion.

/// Maximum number of UTF-16 code units to scan when reading a wide string pointer.
const MAX_WIDE_STRING_LEN: usize = 4096;

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
