use lazy_static::lazy_static;

use crate::{
    avalanche::types::{formatting, packer},
    utils::{hash, vector},
};

pub const ID_LEN: usize = 32;
pub const SHORT_ID_LEN: usize = 20;

lazy_static! {
    static ref EMPTY: Vec<u8> = vec![0; ID_LEN];
    static ref SHORT_EMPTY: Vec<u8> = vec![0; SHORT_ID_LEN];
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ID
#[derive(Debug, Clone)]
pub struct Id {
    pub d: Vec<u8>,
}

impl Default for Id {
    fn default() -> Self {
        Self::default()
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        vector::eq_u8_vectors(&self.d, &other.d)
    }
}
impl Eq for Id {}

impl Id {
    pub fn default() -> Self {
        Self { d: EMPTY.to_vec() }
    }

    /// If the passed array is shorter than the ID_LEN,
    /// it fills in with zero.
    pub fn new(d: &[u8]) -> Self {
        assert!(d.len() <= ID_LEN);
        let mut d: Vec<u8> = Vec::from(d);
        if d.len() < ID_LEN {
            d.resize(ID_LEN, 0);
        }
        Self { d }
    }

    pub fn create_from_str(s: &str) -> Self {
        assert!(s.len() <= ID_LEN);
        let mut d: Vec<u8> = Vec::from(s.as_bytes());
        if d.len() < ID_LEN {
            d.resize(ID_LEN, 0);
        }
        Self { d }
    }

    pub fn empty() -> Self {
        Self { d: EMPTY.to_vec() }
    }

    pub fn is_empty(&self) -> bool {
        (*self) == Self::empty()
    }

    pub fn string(&self) -> String {
        formatting::encode_cb58_with_checksum(&self.d)
    }

    /// ref. "ids.ID.Prefix(output_index)"
    pub fn prefix(&self, prefixes: &[u64]) -> Self {
        let n = prefixes.len() + packer::U64_LEN + 32;
        let packer = packer::Packer::new(n, n);
        for pfx in prefixes {
            packer.pack_u64(*pfx);
        }
        packer.pack_bytes(&self.d);

        let b = packer.take_bytes();
        let d = hash::compute_sha256(&b);
        Self::new(&d)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- avalanche::types::ids::test_ids --exact --show-output
/// ref. "avalanchego/ids.TestIDMarshalJSON"
#[test]
fn test_ids() {
    let id = Id::create_from_str("ava labs");
    assert_eq!(
        id.string(),
        "jvYi6Tn9idMi7BaymUVi9zWjg5tpmW7trfKG1AYJLKZJ2fsU7"
    );
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID
#[derive(Debug, Clone)]
pub struct ShortId {
    pub d: Vec<u8>,
}

impl Default for ShortId {
    fn default() -> Self {
        Self::default()
    }
}

impl PartialEq for ShortId {
    fn eq(&self, other: &Self) -> bool {
        vector::eq_u8_vectors(&self.d, &other.d)
    }
}
impl Eq for ShortId {}

impl ShortId {
    pub fn default() -> Self {
        Self {
            d: SHORT_EMPTY.to_vec(),
        }
    }

    pub fn new(d: &[u8]) -> Self {
        assert_eq!(d.len(), SHORT_ID_LEN);
        let d = Vec::from(d);
        Self { d }
    }

    pub fn empty() -> Self {
        Self {
            d: SHORT_EMPTY.to_vec(),
        }
    }

    pub fn is_empty(&self) -> bool {
        (*self) == Self::empty()
    }

    pub fn string(&self) -> String {
        formatting::encode_cb58_with_checksum(&self.d)
    }
}
