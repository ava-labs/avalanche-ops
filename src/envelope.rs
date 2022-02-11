/// Represents the data encryption key.
#[derive(Debug)]
pub struct DEK {
    pub cipher: Vec<u8>,
    pub plain: Vec<u8>,
}

impl DEK {
    pub fn new(cipher: Vec<u8>, plain: Vec<u8>) -> Self {
        // ref. https://doc.rust-lang.org/1.0.0/style/ownership/constructors.html
        Self { cipher, plain }
    }
}
