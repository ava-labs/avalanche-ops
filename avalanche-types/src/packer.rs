use std::{
    cell::Cell,
    io::{Error, ErrorKind},
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
    /// This is also used for encoding the type IDs from codec.
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
}
