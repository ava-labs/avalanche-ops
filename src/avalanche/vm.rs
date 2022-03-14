use std::io::{self, Error, ErrorKind};

use crate::avalanche::formatting;

/// Generates VM ID based on the name.
pub fn id_from_str(name: &str) -> io::Result<String> {
    let n = name.len();
    if n > 32 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("can't id {} bytes (>32)", n),
        ));
    }

    // "hashing.ToHash256"
    let mut input = name.as_bytes().to_vec();
    input.resize(32, 0);

    // "ids.ToID"
    // "ids.ShortID.String"
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.String
    let short_id = formatting::encode_cb58_with_checksum(&input);
    Ok(short_id)
}

#[test]
fn test_vm_id() {
    use crate::utils::random;
    use log::info;
    let _ = env_logger::builder().is_test(true).try_init();

    let subnet_evm_id = id_from_str("subnet-evm").expect("failed to generate id from str");
    assert_eq!(
        subnet_evm_id,
        "srEXiWaHiToEaT9YAQ4Za3ExGKTGm4iGjtnrBnmKN2eZtjn6u"
    );

    let contents = random::string(30);
    let id_from_str = id_from_str(&contents).expect("failed to generate id from str");
    info!("id_from_str: {}", id_from_str);
}
