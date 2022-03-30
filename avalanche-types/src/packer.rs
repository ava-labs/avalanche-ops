use std::{
    cell::Cell,
    io::{self, Error, ErrorKind},
    u16,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};

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
    pub bytes: Cell<BytesMut>,
    /// offset that is being written to in the byte array
    pub offset: Cell<usize>,
    /// tracks the last error if any
    pub error: Cell<Option<Error>>,
}

impl Packer {
    pub fn new(max_size: usize, initial_cap: usize) -> Self {
        let bytes = Cell::new(BytesMut::with_capacity(initial_cap));
        let offset = Cell::new(0);
        Self {
            max_size,
            bytes,
            offset,
            error: Cell::new(None),
        }
    }

    /// Create a new packer from the existing bytes.
    /// Resets the offset to the end of the existing bytes.
    pub fn load_bytes_for_pack(max_size: usize, b: &[u8]) -> Self {
        Self {
            max_size,
            bytes: Cell::new(BytesMut::from(b)),
            offset: Cell::new(b.len()),
            error: Cell::new(None),
        }
    }

    /// Create a new packer from the existing bytes.
    /// Resets the offset to the beginning of the existing bytes.
    pub fn load_bytes_for_unpack(max_size: usize, b: &[u8]) -> Self {
        Self {
            max_size,
            bytes: Cell::new(BytesMut::from(b)),
            offset: Cell::new(0),
            error: Cell::new(None),
        }
    }

    /// Returns the current bytes array as an immutable bytes array.
    /// Be cautious! Once bytes are taken out, the "bytes" field is set to default (empty).
    /// TODO: make sure this does shallow copy!
    pub fn take_bytes(&self) -> Bytes {
        let mut b = self.bytes.take();
        let n = b.len();
        let immutable_bytes = b.copy_to_bytes(n);
        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);
        immutable_bytes
    }

    /// Sets the current bytes array as an immutable bytes array.
    /// Useful to reuse packer after calling "take_bytes", which
    /// makes the "bytes" field default (empty).
    pub fn set_bytes(&self, b: &[u8]) {
        self.bytes.set(BytesMut::from(b));
    }

    pub fn errored(&self) -> bool {
        let err = self.error.take();
        let errored = err.is_some();
        self.error.set(err);
        errored
    }

    fn set_error(&self, err: Error) {
        self.error.set(Some(err));
    }

    /// Updates the "offset" field.
    fn set_offset(&self, offset: usize) {
        self.offset.set(offset)
    }

    /// Returns the "offset" value.
    pub fn get_offset(&self) -> usize {
        // "usize" implements "Copy" so just use "get" on "Cell"
        // ref. https://doc.rust-lang.org/std/cell/struct.Cell.html#impl-1
        self.offset.get()
    }

    /// Returns the current length of the bytes array.
    pub fn bytes_len(&self) -> usize {
        // "BytesMut" does not implement "Copy" so take/update/set it back
        // ref. https://doc.rust-lang.org/std/cell/struct.Cell.html#impl-1
        let b = self.bytes.take();
        let n = b.len();
        self.bytes.set(b);
        n
    }

    /// Returns the current capacity of the bytes array.
    pub fn bytes_cap(&self) -> usize {
        // "BytesMut" does not implement "Copy" so take/update/set it back
        // ref. https://doc.rust-lang.org/std/cell/struct.Cell.html#impl-1
        let b = self.bytes.take();
        let n = b.capacity();
        self.bytes.set(b);
        n
    }

    /// Truncates the bytes array while retaining the underlying capacity.
    fn trucate_bytes_with_length(&self, len: usize) {
        // "BytesMut" does not implement "Copy" so take/update/set it back
        // remember to put it back -- "take" leaves the field as "Default::default()"
        // ref. https://doc.rust-lang.org/std/cell/struct.Cell.html#impl-1
        let mut b = self.bytes.take();
        b.truncate(len);
        self.bytes.set(b);
    }

    /// Reserves the bytes array while retaining the underlying length.
    fn reserve_bytes_with_length(&self, len: usize) {
        // "BytesMut" does not implement "Copy" so take/update/set it back
        // remember to put it back -- "take" leaves the field as "Default::default()"
        // ref. https://doc.rust-lang.org/std/cell/struct.Cell.html#impl-1
        let mut b = self.bytes.take();
        b.reserve(len);
        self.bytes.set(b);
    }

    /// Ensures the remaining capacity of the bytes array
    /// so it can write "n" bytes to the array.
    /// ref. "avalanchego/utils/wrappers.Packer.Expand"
    pub fn expand(&self, n: usize) {
        // total number of bytes that must be remained in the bytes array
        let needed_size = self.get_offset() + n;

        // already has sufficient length
        // thus no need to check max_size
        if needed_size <= self.bytes_len() {
            return;
        }

        // byte slice would cause it to grow too large (out of bounds)
        if needed_size > self.max_size {
            self.set_error(Error::new(
                ErrorKind::InvalidInput,
                format!("needed_size {} > max_size {}", needed_size, self.max_size),
            ));
            return;
        }

        // has sufficient capacity to lengthen it without mem alloc
        let bytes_cap = self.bytes_cap();
        if needed_size <= bytes_cap {
            self.trucate_bytes_with_length(needed_size);
            return;
        }

        // "avalanchego/utils/wrappers.Packer.Expand" is different in that
        // it uses "resize" to fill in the array with zero values.
        // As long as we maintain the "offset", it does not change the underlying
        // packing algorithm, thus compatible.
        self.reserve_bytes_with_length(needed_size);
    }

    /// Sets an error if the packer has insufficient lenght for the input size.
    /// ref. "avalanchego/utils/wrappers.Packer.CheckSpace"
    pub fn check_space(&self, n: usize) {
        let needed_size = self.get_offset() + n;
        if needed_size > self.bytes_len() {
            self.set_error(Error::new(
                ErrorKind::InvalidInput,
                "packer has insufficient length for input", // ref. "errBadLength"
            ));
        };
    }

    /// Writes the "u8" value at the offset and increments the offset afterwards.
    /// ref. "avalanchego/utils/wrappers.Packer.PackByte"
    pub fn pack_byte(&self, v: u8) {
        self.expand(BYTE_LEN);
        if self.errored() {
            return;
        }

        let offset = self.get_offset();
        let mut b = self.bytes.take();

        // assume "offset" is not updated by the other "unpack*"
        // thus no need to keep internal cursor in sync with "offset"
        // unsafe { b.advance_mut(offset) };

        // writes an unsigned 8-bit integer
        b.put_u8(v);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        // "put_u8" already advances the current position by BYTE_LEN
        // thus no need for "unsafe { b.advance_mut(offset + BYTE_LEN) };"
        // ref. https://docs.rs/bytes/latest/bytes/buf/trait.BufMut.html#method.put_u8
        self.set_offset(offset + BYTE_LEN);
    }

    /// Unpacks the byte in the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackByte"
    pub fn unpack_byte(&self) -> u8 {
        self.check_space(BYTE_LEN);
        if self.errored() {
            return BYTE_SENTINEL;
        }

        let offset = self.get_offset();
        let b = self.bytes.take();

        let p = &b[offset];
        let v = *p;

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        self.set_offset(offset + BYTE_LEN);
        v
    }

    /// Writes the "u16" value at the offset and increments the offset afterwards.
    /// ref. "avalanchego/utils/wrappers.Packer.PackShort"
    pub fn pack_u16(&self, v: u16) {
        self.expand(U16_LEN);
        if self.errored() {
            return;
        }

        let offset = self.get_offset();
        let mut b = self.bytes.take();

        // assume "offset" is not updated by the other "unpack*"
        // thus no need to keep internal cursor in sync with "offset"
        // unsafe { b.advance_mut(offset) };

        // writes an unsigned 16 bit integer in big-endian byte order
        // ref. "binary.BigEndian.PutUint16"
        b.put_u16(v);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        // "put_u16" already advances the current position by U16_LEN
        // thus no need for "unsafe { b.advance_mut(offset + U16_LEN) };"
        // ref. https://docs.rs/bytes/latest/bytes/buf/trait.BufMut.html#method.put_u16
        self.set_offset(offset + U16_LEN);
    }

    /// Unpacks the u16 from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackShort"
    pub fn unpack_u16(&self) -> u16 {
        self.check_space(U16_LEN);
        if self.errored() {
            return U16_SENTINEL;
        }

        let offset = self.get_offset();
        let b = self.bytes.take();

        let pos = &b[offset..offset + U16_LEN];

        // ref. "binary.BigEndian.Uint16"
        // ref. https://doc.rust-lang.org/std/primitive.u16.html#method.from_be_bytes
        let v = u16::from_be_bytes([pos[0], pos[1]]);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        self.set_offset(offset + U16_LEN);
        v
    }

    /// Writes the "u32" value at the offset and increments the offset afterwards.
    /// ref. "avalanchego/utils/wrappers.Packer.PackInt"
    pub fn pack_u32(&self, v: u32) {
        self.expand(U32_LEN);
        if self.errored() {
            return;
        }

        let offset = self.get_offset();
        let mut b = self.bytes.take();

        // assume "offset" is not updated by the other "unpack*"
        // thus no need to keep internal cursor in sync with "offset"
        // unsafe { b.advance_mut(offset) };

        // writes an unsigned 32 bit integer in big-endian byte order
        // ref. "binary.BigEndian.PutUint32"
        b.put_u32(v);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        // "put_u32" already advances the current position by U32_LEN
        // thus no need for "unsafe { b.advance_mut(offset + U32_LEN) };"
        // ref. https://docs.rs/bytes/latest/bytes/buf/trait.BufMut.html#method.put_u32
        self.set_offset(offset + U32_LEN);
    }

    /// Unpacks the u32 from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackInt"
    pub fn unpack_u32(&self) -> u32 {
        self.check_space(U32_LEN);
        if self.errored() {
            return U32_SENTINEL;
        }

        let offset = self.get_offset();
        let b = self.bytes.take();

        let pos = &b[offset..offset + U32_LEN];

        // ref. "binary.BigEndian.Uint32"
        // ref. https://doc.rust-lang.org/std/primitive.u32.html#method.from_be_bytes
        let v = u32::from_be_bytes([pos[0], pos[1], pos[2], pos[3]]);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        self.set_offset(offset + U32_LEN);
        v
    }

    /// Writes the "u64" value at the offset and increments the offset afterwards.
    /// ref. "avalanchego/utils/wrappers.Packer.PackLong"
    pub fn pack_u64(&self, v: u64) {
        self.expand(U64_LEN);
        if self.errored() {
            return;
        }

        let offset = self.get_offset();
        let mut b = self.bytes.take();

        // assume "offset" is not updated by the other "unpack*"
        // thus no need to keep internal cursor in sync with "offset"
        // unsafe { b.advance_mut(offset) };

        // writes an unsigned 64 bit integer in big-endian byte order
        // ref. "binary.BigEndian.PutUint64"
        b.put_u64(v);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        // "put_u64" already advances the current position by U64_LEN
        // thus no need for "unsafe { b.advance_mut(offset + U64_LEN) };"
        // ref. https://docs.rs/bytes/latest/bytes/buf/trait.BufMut.html#method.put_u64
        self.set_offset(offset + U64_LEN);
    }

    /// Unpacks the u64 from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackLong"
    pub fn unpack_u64(&self) -> u64 {
        self.check_space(U64_LEN);
        if self.errored() {
            return U64_SENTINEL;
        }

        let offset = self.get_offset();
        let b = self.bytes.take();

        let pos = &b[offset..offset + U64_LEN];

        // ref. "binary.BigEndian.Uint64"
        // ref. https://doc.rust-lang.org/std/primitive.u64.html#method.from_be_bytes
        let v = u64::from_be_bytes([
            pos[0], pos[1], pos[2], pos[3], pos[4], pos[5], pos[6], pos[7],
        ]);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        self.set_offset(offset + U64_LEN);
        v
    }

    /// Writes the "bool" value at the offset and increments the offset afterwards.
    /// ref. "avalanchego/utils/wrappers.Packer.PackBool"
    pub fn pack_bool(&self, v: bool) {
        if v {
            self.pack_byte(1)
        } else {
            self.pack_byte(0)
        }
    }

    /// Unpacks the bool in the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackBool"
    pub fn unpack_bool(&self) -> bool {
        match self.unpack_byte() {
            0 => false,
            1 => true,
            _ => {
                self.set_error(Error::new(
                    ErrorKind::InvalidInput,
                    "unexpected value when unpacking bool", // ref. "errBadBool"
                ));
                false
            }
        }
    }

    /// Writes the "u8" slice from the offset and increments the offset as much.
    /// ref. "avalanchego/utils/wrappers.Packer.PackFixedBytes"
    pub fn pack_bytes(&self, v: &[u8]) {
        let n = v.len();
        self.expand(n);
        if self.errored() {
            return;
        }

        let offset = self.get_offset();
        let mut b = self.bytes.take();

        // assume "offset" is not updated by the other "unpack*"
        // thus no need to keep internal cursor in sync with "offset"
        // unsafe { b.advance_mut(offset) };

        // writes bytes from the offset
        // ref. "copy(p.Bytes[p.Offset:], bytes)"
        b.put_slice(v);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        // "put_slice" already advances the current position by "n"
        // thus no need for "unsafe { b.advance_mut(offset + n) };"
        // ref. https://docs.rs/bytes/latest/bytes/buf/trait.BufMut.html#method.put_u64
        self.set_offset(offset + n);
    }

    /// Unpacks the "u8" slice from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackFixedBytes"
    pub fn unpack_bytes(&self, n: usize) -> Option<Vec<u8>> {
        self.check_space(n);
        if self.errored() {
            return None;
        }

        let offset = self.get_offset();
        let b = self.bytes.take();

        let pos = &b[offset..offset + n];
        let v = Vec::from(pos);

        // remember to put it back -- "take" leaves the field as "Default::default()"
        self.bytes.set(b);

        self.set_offset(offset + n);
        Some(v)
    }

    /// Writes the "u8" slice from the offset and increments the offset as much.
    /// The first 4-byte is used for encoding lengh header.
    /// ref. "avalanchego/utils/wrappers.Packer.PackBytes"
    pub fn pack_bytes_with_header(&self, v: &[u8]) {
        let n = v.len();
        self.pack_u32(n as u32);
        self.pack_bytes(v);
    }

    /// Unpacks the "u8" slice from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackBytes"
    pub fn unpack_bytes_with_header(&self) -> Option<Vec<u8>> {
        let n = self.unpack_u32();
        self.unpack_bytes(n as usize)
    }

    /// Writes the two-dimensional "u8" slice from the offset and increments the offset as much.
    /// ref. "avalanchego/utils/wrappers.Packer.PackFixedByteSlices"
    pub fn pack_2d_bytes(&self, v: Vec<Vec<u8>>) {
        let n = v.len();
        self.pack_u32(n as u32);
        for vv in v.iter() {
            self.pack_bytes(vv);
        }
    }

    /// Unpacks the two-dimensional "u8" slice from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackFixedByteSlices"
    pub fn unpack_2d_bytes(&self, n: usize) -> Option<Vec<Vec<u8>>> {
        let slices = self.unpack_u32();
        if self.errored() {
            return None;
        }

        let mut rs: Vec<Vec<u8>> = Vec::new();
        for _ in 0..slices {
            let b = self.unpack_bytes(n as usize);
            if b.is_none() || self.errored() {
                return None;
            }
            rs.push(b.unwrap());
        }
        Some(rs)
    }

    /// Writes the two-dimensional "u8" slice from the offset and increments the offset as much.
    /// ref. "avalanchego/utils/wrappers.Packer.Pack2DByteSlice"
    pub fn pack_2d_bytes_with_header(&self, v: Vec<Vec<u8>>) {
        let n = v.len();
        self.pack_u32(n as u32);
        for vv in v.iter() {
            self.pack_bytes_with_header(vv);
        }
    }

    /// Unpacks the two-dimensional "u8" slice from the "offset" position,
    /// and advances the cursor and offset.
    /// ref. "avalanchego/utils/wrappers.Packer.Unpack2DByteSlice"
    pub fn unpack_2d_bytes_with_header(&self) -> Option<Vec<Vec<u8>>> {
        let slices = self.unpack_u32();
        if self.errored() {
            return None;
        }

        let mut rs: Vec<Vec<u8>> = Vec::new();
        for _ in 0..slices {
            let b = self.unpack_bytes_with_header();
            if b.is_none() || self.errored() {
                return None;
            }
            rs.push(b.unwrap());
        }
        Some(rs)
    }

    /// Writes str from the offset and increments the offset as much.
    /// ref. "avalanchego/utils/wrappers.Packer.PackStr"
    pub fn pack_str(&self, v: &str) {
        let n = v.len() as u16;
        if n > MAX_STR_LEN {
            self.set_error(Error::new(
                ErrorKind::InvalidInput,
                format!("str {} > max_size {}", n, MAX_STR_LEN),
            ));
            return;
        }
        self.pack_u16(n);
        self.pack_bytes(v.as_bytes());
    }

    /// Unpacks str from the offset.
    /// ref. "avalanchego/utils/wrappers.Packer.UnpackStr"
    /// TODO: Go "UnpackStr" does deep-copy of bytes to "string" cast
    ///       Can we bypass deep-copy by passing around bytes?
    ///       ref. https://github.com/golang/go/issues/25484
    pub fn unpack_str(&self) -> io::Result<Option<String>> {
        let n = self.unpack_u16();
        let d = self.unpack_bytes(n as usize);
        if d.is_none() {
            return Ok(None);
        }

        let d = d.unwrap();
        let s = match String::from_utf8(d) {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("failed String::from_utf8 {}", e),
                ));
            }
        };
        Ok(Some(s))
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_expand --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerExpand"
#[test]
fn test_expand() {
    let s: Vec<u8> = vec![0x01];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(2),
        error: Cell::new(None),
    };
    packer.expand(1);
    assert!(packer.errored());

    let s: Vec<u8> = vec![0x01, 0x02, 0x03];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.expand(1);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 3);

    // 256 KiB
    let packer = Packer::new(256 * 1024, 128);
    packer.expand(10000);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 0);
    assert_eq!(packer.bytes_cap(), 10000);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_packer_from_bytes --exact --show-output
#[test]
fn test_packer_from_bytes() {
    let s: Vec<u8> = vec![0x01, 0x02, 0x03];
    let packer = Packer::load_bytes_for_pack(10000, &s);
    packer.pack_byte(0x10);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 4);
    assert_eq!(packer.get_offset(), 4);

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x01\x02\x03\x10");
    let expected: Vec<u8> = vec![0x01, 0x02, 0x03, 0x10];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_byte --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackByte"
#[test]
fn test_pack_byte() {
    let packer = Packer::new(1, 0);
    packer.pack_byte(0x01);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 1);
    assert_eq!(packer.get_offset(), 1);

    packer.pack_byte(0x02);
    assert!(packer.errored());
    assert_eq!(packer.bytes_len(), 1);
    assert_eq!(packer.get_offset(), 1);

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x01");
    let expected: Vec<u8> = vec![0x01];
    assert_eq!(&b[..], &expected[..]);
    assert_eq!(packer.bytes_len(), 0);
    assert_eq!(packer.get_offset(), 1);

    packer.set_bytes(&b);
    assert_eq!(packer.bytes_len(), 1);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_byte --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackByte"
#[test]
fn test_unpack_byte() {
    let s: Vec<u8> = vec![0x01];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_byte();
    assert!(!packer.errored());
    assert_eq!(b, 1);
    assert_eq!(packer.get_offset(), 1);

    let b = packer.unpack_byte();
    assert!(packer.errored());
    assert_eq!(b, BYTE_SENTINEL);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_u16 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackShort"
#[test]
fn test_pack_u16() {
    let packer = Packer {
        max_size: U16_LEN,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_u16(0x0102);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), U16_LEN);

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x01\x02");
    let expected: Vec<u8> = vec![0x01, 0x02];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_u16 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackShort"
#[test]
fn test_unpack_u16() {
    let s: Vec<u8> = vec![0x01, 0x02];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_u16();
    assert!(!packer.errored());
    assert_eq!(b, 0x0102);
    assert_eq!(packer.get_offset(), U16_LEN);

    let b = packer.unpack_u16();
    assert!(packer.errored());
    assert_eq!(b, U16_SENTINEL);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_u16_short --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPacker"
#[test]
fn test_pack_u16_short() {
    let packer = Packer {
        max_size: 3,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };

    packer.pack_u16(17);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 2);

    packer.pack_u16(1);
    assert!(packer.errored());

    let b = packer.take_bytes();
    let expected: Vec<u8> = vec![0x00, 17];
    assert_eq!(&b[..], &expected[..]);

    let s: Vec<u8> = vec![0x00, 17];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_u16();
    assert!(!packer.errored());
    assert_eq!(b, 17);
    assert_eq!(packer.get_offset(), U16_LEN);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_u32 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackInt"
#[test]
fn test_pack_u32() {
    let packer = Packer {
        max_size: U32_LEN,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_u32(0x01020304);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), U32_LEN);

    packer.pack_u32(0x05060708);
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x01\x02\x03\x04");
    let expected: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_u32 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackInt"
#[test]
fn test_unpack_u32() {
    let s: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_u32();
    assert!(!packer.errored());
    assert_eq!(b, 0x01020304);
    assert_eq!(packer.get_offset(), U32_LEN);

    let b = packer.unpack_u32();
    assert!(packer.errored());
    assert_eq!(b, U32_SENTINEL);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_u64 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackLong"
#[test]
fn test_pack_u64() {
    let packer = Packer {
        max_size: U64_LEN,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_u64(0x0102030405060708);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), U64_LEN);

    // beyond max size
    packer.pack_u64(0x090a0b0c0d0e0f00);
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x01\x02\x03\x04\x05\x06\x07\x08");
    let expected: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_u64 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackLong"
#[test]
fn test_unpack_u64() {
    let s: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_u64();
    assert!(!packer.errored());
    assert_eq!(b, 0x0102030405060708);
    assert_eq!(packer.get_offset(), U64_LEN);

    let b = packer.unpack_u64();
    assert!(packer.errored());
    assert_eq!(b, U64_SENTINEL);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_bool --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackBool"
/// ref. "avalanchego/utils/wrappers.TestPackerPackBool"
#[test]
fn test_pack_bool() {
    let packer = Packer {
        max_size: 3,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_bool(false);
    packer.pack_bool(true);
    packer.pack_bool(false);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 3);

    packer.pack_bool(true);
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x00\x01\x00");
    let expected: Vec<u8> = vec![0x00, 0x01, 0x00];
    assert_eq!(&b[..], &expected[..]);

    let b = BytesMut::from(&expected[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_bool();
    assert_eq!(b, false);
    let b = packer.unpack_bool();
    assert_eq!(b, true);
    let b = packer.unpack_bool();
    assert_eq!(b, false);
    assert!(!packer.errored());
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_bool --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackBool"
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackBool"
#[test]
fn test_unpack_bool() {
    let s: Vec<u8> = vec![0x01];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_bool();
    assert!(!packer.errored());
    assert!(b);
    assert_eq!(packer.get_offset(), BOOL_LEN);

    let b = packer.unpack_bool();
    assert!(packer.errored());
    assert_eq!(b, BOOL_SENTINEL);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_bytes --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackFixedBytes"
#[test]
fn test_pack_bytes() {
    let packer = Packer {
        max_size: 8,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };

    let s = "Avax";
    packer.pack_bytes(s.as_bytes());
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 4);

    packer.pack_bytes(s.as_bytes());
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 8);

    // beyond max size
    packer.pack_bytes(s.as_bytes());
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"AvaxAvax");
    let expected: Vec<u8> = vec![65, 118, 97, 120, 65, 118, 97, 120];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_bytes --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackFixedBytes"
#[test]
fn test_unpack_bytes() {
    let s: Vec<u8> = vec![65, 118, 97, 120];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_bytes(4).unwrap();
    assert!(!packer.errored());
    assert_eq!(&b[..], b"Avax");
    assert_eq!(packer.get_offset(), 4);

    let b = packer.unpack_bytes(4);
    assert!(packer.errored());
    assert!(b.is_none());
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_bytes_with_header --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackBytes"
#[test]
fn test_pack_bytes_with_header() {
    let packer = Packer {
        max_size: 8,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };

    let s = "Avax";
    packer.pack_bytes_with_header(s.as_bytes());
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 8);

    // beyond max size
    packer.pack_bytes_with_header(s.as_bytes());
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x00\x00\x00\x04Avax");
    let expected: Vec<u8> = vec![0x00, 0x00, 0x00, 0x04, 65, 118, 97, 120];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_bytes_with_header --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackBytes"
#[test]
fn test_unpack_bytes_with_header() {
    let s: Vec<u8> = vec![0x00, 0x00, 0x00, 0x04, 65, 118, 97, 120];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_bytes_with_header().unwrap();
    assert!(!packer.errored());
    assert_eq!(&b[..], b"Avax");
    assert_eq!(packer.get_offset(), 8);

    let b = packer.unpack_bytes_with_header();
    assert!(packer.errored());
    assert!(b.is_none());
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_2d_bytes --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerPackFixedByteSlices"
#[test]
fn test_pack_2d_bytes() {
    let packer = Packer {
        max_size: 12,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };

    // first 4-byte is for length
    let s1 = "Avax";
    let s2 = "Evax";
    packer.pack_2d_bytes(Vec::from(vec![
        Vec::from(s1.as_bytes()),
        Vec::from(s2.as_bytes()),
    ]));
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 12);

    // beyond max size
    packer.pack_2d_bytes(Vec::from(vec![
        Vec::from(s1.as_bytes()),
        Vec::from(s2.as_bytes()),
    ]));
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x00\x00\x00\x02AvaxEvax");
    let expected: Vec<u8> = vec![0x00, 0x00, 0x00, 0x02, 65, 118, 97, 120, 69, 118, 97, 120];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_2d_bytes --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerUnpackFixedByteSlices"
#[test]
fn test_unpack_2d_bytes() {
    let s: Vec<u8> = vec![0x00, 0x00, 0x00, 0x02, 65, 118, 97, 120, 69, 118, 97, 120];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_2d_bytes(4).unwrap();
    assert!(!packer.errored());
    assert_eq!(
        &b[..],
        Vec::from(vec![
            Vec::from("Avax".as_bytes()),
            Vec::from("Evax".as_bytes()),
        ])
    );
    assert_eq!(packer.get_offset(), 12);

    let b = packer.unpack_2d_bytes(4);
    assert!(packer.errored());
    assert!(b.is_none());
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_2d_bytes_with_header --exact --show-output
#[test]
fn test_pack_2d_bytes_with_header() {
    let packer = Packer {
        max_size: 1024,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };

    // first 4-byte is for length
    // two more 4-bytes for each length
    let s1 = "Avax";
    let s2 = "Evax";
    packer.pack_2d_bytes_with_header(Vec::from(vec![
        Vec::from(s1.as_bytes()),
        Vec::from(s2.as_bytes()),
    ]));
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 20); // 4*3 + 4*2

    let b = packer.take_bytes();
    assert_eq!(
        &b[..],
        b"\x00\x00\x00\x02\x00\x00\x00\x04Avax\x00\x00\x00\x04Evax"
    );
    let expected: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 65, 118, 97, 120, 0x00, 0x00, 0x00, 0x04,
        69, 118, 97, 120,
    ];
    assert_eq!(&b[..], &expected[..]);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_unpack_2d_bytes_with_header --exact --show-output
#[test]
fn test_unpack_2d_bytes_with_header() {
    let s: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 65, 118, 97, 120, 0x00, 0x00, 0x00, 0x04,
        69, 118, 97, 120,
    ];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 0,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_2d_bytes_with_header().unwrap();
    assert!(!packer.errored());
    assert_eq!(
        &b[..],
        Vec::from(vec![
            Vec::from("Avax".as_bytes()),
            Vec::from("Evax".as_bytes()),
        ])
    );
    assert_eq!(packer.get_offset(), 20);

    let b = packer.unpack_2d_bytes_with_header();
    assert!(packer.errored());
    assert!(b.is_none());
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_2d_bytes_with_header_123 --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPacker2DByteSlice"
#[test]
fn test_pack_2d_bytes_with_header_123() {
    // case 1; empty
    let packer = Packer {
        max_size: 1024,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_2d_bytes_with_header(Vec::from(vec![]));
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 4);
    assert!(packer.unpack_2d_bytes_with_header().is_none());
    assert!(packer.errored());

    // case 2; only one dimension
    let packer = Packer {
        max_size: 1024,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_2d_bytes_with_header(Vec::from(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]));
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 4 + 4 + 10);

    let b = packer.take_bytes();
    let expected: Vec<u8> = vec![0, 0, 0, 1, 0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    assert_eq!(&b[..], &expected[..]);

    let s: Vec<u8> = vec![0, 0, 0, 1, 0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 1024,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_2d_bytes_with_header().unwrap();
    assert!(!packer.errored());
    assert_eq!(&b[..], Vec::from(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]));
    assert_eq!(packer.get_offset(), 4 + 4 + 10);

    // case 3; two dimensions
    let packer = Packer {
        max_size: 1024,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    packer.pack_2d_bytes_with_header(Vec::from(vec![
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        vec![11, 12, 3, 4, 5, 6, 7, 8, 9, 10],
    ]));
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 4 + 4 + 10 + 4 + 10);

    let b = packer.take_bytes();
    let expected: Vec<u8> = vec![
        0, 0, 0, 2, 0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 10, 11, 12, 3, 4, 5, 6, 7,
        8, 9, 10,
    ];
    assert_eq!(&b[..], &expected[..]);

    let s: Vec<u8> = vec![
        0, 0, 0, 2, 0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 10, 11, 12, 3, 4, 5, 6, 7,
        8, 9, 10,
    ];
    let b = BytesMut::from(&s[..]);
    let packer = Packer {
        max_size: 1024,
        bytes: Cell::new(b),
        offset: Cell::new(0),
        error: Cell::new(None),
    };
    let b = packer.unpack_2d_bytes_with_header().unwrap();
    assert!(!packer.errored());
    assert_eq!(
        &b[..],
        Vec::from(vec![
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            vec![11, 12, 3, 4, 5, 6, 7, 8, 9, 10],
        ])
    );
    assert_eq!(packer.get_offset(), 4 + 4 + 10 + 4 + 10);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- packer::test_pack_str --exact --show-output
/// ref. "avalanchego/utils/wrappers.TestPackerString"
#[test]
fn test_pack_str() {
    let packer = Packer {
        max_size: 6,
        bytes: Cell::new(BytesMut::with_capacity(0)),
        offset: Cell::new(0),
        error: Cell::new(None),
    };

    let s = "Avax";
    packer.pack_str(s);
    assert!(!packer.errored());
    assert_eq!(packer.bytes_len(), 2 + 4);

    // beyond max size
    packer.pack_str(s);
    assert!(packer.errored());

    let b = packer.take_bytes();
    assert_eq!(&b[..], b"\x00\x04Avax");
    let expected: Vec<u8> = vec![0x00, 0x04, 65, 118, 97, 120];
    assert_eq!(&b[..], &expected[..]);
}
