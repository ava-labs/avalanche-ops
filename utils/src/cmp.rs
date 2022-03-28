pub fn eq_u8_vectors(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) && va.iter().zip(vb).all(|(a, b)| *a == *b)
}
