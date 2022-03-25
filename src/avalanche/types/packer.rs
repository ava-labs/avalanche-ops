use std::u16;

pub const MAX_STR_LEN: u16 = u16::MAX - 1;

/// number of bytes per byte
/// 8-bit unsigned integer, so the length is 1-byte
pub const BYTE_LEN: usize = 1;
pub const BYTE_SENTINEL: u8 = 0;

/// number of bytes per short
/// 16-bit unsigned integer, so the length is 2-byte
pub const U16_LEN: usize = 2;
pub const U16_SENTINEL: u16 = 0;

/// number of bytes per int
/// 32-bit unsigned integer, so the length is 4-byte
pub const U32_LEN: usize = 4;
pub const U32_SENTINEL: u32 = 0;

/// number of bytes per long
/// 64-bit unsigned integer, so the length is 8-byte
pub const U64_LEN: usize = 8;
pub const U64_SENTINEL: u64 = 0;

/// number of bytes per bool
pub const BOOL_LEN: usize = 1;
pub const BOOL_SENTINEL: bool = false;

/// number of bytes per IP
pub const IP_LEN: usize = 16 + U16_LEN;

/// ref. "avalanchego/utils/wrapper.Packer"
/// ref. https://doc.rust-lang.org/1.7.0/book/mutability.html
/// ref. https://doc.rust-lang.org/std/cell/struct.Cell.html
pub struct Packer {
    /// largest allowed size of expanding the byte array
    pub max_size: usize,
    /// current byte array
    // pub bytes: ...
    /// offset that is being written to in the byte array
    pub offset: Cell<usize>,
    /// tracks the last error if any
    pub error: Cell<Option<Error>>,
}
