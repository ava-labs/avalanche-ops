use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use log::info;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509Builder, X509NameBuilder},
};

/// Generates a X509 certificate pair.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/staking#NewCertAndKeyBytes
pub fn generate(key_path: &str, cert_path: &str) -> io::Result<()> {
    info!(
        "creating certs with key path {} and cert path {}",
        key_path, cert_path
    );
    if Path::new(key_path).exists() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("key path {} already exists", key_path),
        ));
    }
    if Path::new(cert_path).exists() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("cert path {} already exists", cert_path),
        ));
    }

    // generate a 4096-bit RSA key pair
    let rsa = Rsa::generate(4096).unwrap();
    let priv_key = PKey::from_rsa(rsa).unwrap();

    // [optional] to save public key
    // let pub_key: Vec<u8> = priv_key.public_key_to_pem().unwrap();
    // String::from_utf8(pub_key.to_vec()).unwrap();

    let mut cert_builder = X509Builder::new().unwrap();

    let mut issuer = X509NameBuilder::new().unwrap();
    issuer.append_entry_by_text("C", "US").unwrap();
    issuer.append_entry_by_text("ST", "NY").unwrap();
    issuer.append_entry_by_text("O", "Ava Labs").unwrap();
    issuer.append_entry_by_text("CN", "avalanche-ops").unwrap();
    let issuer = issuer.build();
    cert_builder.set_subject_name(issuer.as_ref()).unwrap();
    cert_builder.set_issuer_name(issuer.as_ref()).unwrap();

    // go/src/crypto/x509/x509.go sets "Version" to 2 by default
    // zero-indexed thus this is TLS v3
    cert_builder.set_version(2).unwrap();

    let zero = BigNum::from_u32(0)?;
    let zero = zero.to_asn1_integer()?;
    cert_builder.set_serial_number(zero.as_ref())?;

    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(not_before.as_ref())?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(not_after.as_ref())?;

    cert_builder.set_pubkey(priv_key.as_ref()).unwrap();
    cert_builder
        .sign(priv_key.as_ref(), MessageDigest::sha256())
        .unwrap();

    let cert = cert_builder.build();
    let cert_ref = cert.as_ref();
    let cert_contents = cert_ref.to_pem().unwrap();
    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(&cert_contents[..])?;
    info!("saved cert {}", cert_path);

    // OpenSSL 0.9.8 generates PKCS #1 private keys by default
    // while OpenSSL 1.0.0 generates PKCS #8 keys.
    // ref. "crypto/tls.parsePrivateKey"
    // ref. "crypto/x509.MarshalPKCS8PrivateKey"
    let key_contents = priv_key.private_key_to_pem_pkcs8().unwrap();
    let mut key_file = File::create(key_path)?;
    key_file.write_all(&key_contents[..])?;
    info!("saved key {}", key_path);

    Ok(())
}

#[test]
fn test_cert() {
    use crate::utils::random;
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

    let tmp_dir = tempfile::tempdir().unwrap();

    let key_path = tmp_dir.path().join(random::string(20));
    let key_path = key_path.as_os_str().to_str().unwrap();
    let mut key_path = String::from(key_path);
    key_path.push_str(".key");

    let cert_path = tmp_dir.path().join(random::string(20));
    let cert_path = cert_path.as_os_str().to_str().unwrap();
    let mut cert_path = String::from(cert_path);
    cert_path.push_str(".cert");

    let ret = generate(&key_path, &cert_path);
    assert!(ret.is_ok());

    let key_contents = fs::read(key_path).unwrap();
    let key_contents = String::from_utf8(key_contents.to_vec()).unwrap();
    info!("key: {} bytes", key_contents.len());

    // openssl x509 -in [cert_path] -text -noout
    let cert_contents = fs::read(cert_path).unwrap();
    let cert_contents = String::from_utf8(cert_contents.to_vec()).unwrap();
    info!("cert: {} bytes", cert_contents.len());
}
