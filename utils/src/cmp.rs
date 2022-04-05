pub fn eq_vectors<T>(va: &[T], vb: &[T]) -> bool
where
    T: Eq,
{
    (va.len() == vb.len()) && va.iter().zip(vb).all(|(a, b)| *a == *b)
}

pub fn is_sorted_and_unique<T>(data: &[T]) -> bool
where
    T: Ord,
{
    data.windows(2).all(|w| w[0] < w[1])
}
