use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use log::info;
use rcgen::{date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType};

/// Generates a X509 certificate pair.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/staking#NewCertAndKeyBytes
///
/// See https://github.com/ava-labs/avalanche-ops/blob/ad1730ed193cf1cd5056f23d130c3defc897cab5/avalanche-types/src/cert.rs
/// to use "openssl" crate.
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

    let mut cert_params: CertificateParams = Default::default();

    // this fails peer IP verification (e.g., incorrect signature)
    // cert_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    //
    // currently, "avalanchego" only signs the IP with "crypto.SHA256"
    // ref. "avalanchego/network/ip_signer.go.newIPSigner"
    // ref. "avalanchego/network/peer/ip.go UnsignedIP.Sign" with "crypto.SHA256"
    //
    // TODO: support sha384/512 signatures in avalanchego node
    cert_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

    cert_params.not_before = date_time_ymd(2022, 1, 1);
    cert_params.not_after = date_time_ymd(5000, 1, 1);
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CountryName, "US");
    cert_params
        .distinguished_name
        .push(DnType::StateOrProvinceName, "NY");
    cert_params
        .distinguished_name
        .push(DnType::OrganizationName, "Ava Labs");
    cert_params
        .distinguished_name
        .push(DnType::CommonName, "avalanche-ops");
    let cert = Certificate::from_params(cert_params).map_err(|e| {
        return Error::new(
            ErrorKind::Other,
            format!("failed to generate certificate {}", e),
        );
    })?;
    let cert_contents = cert.serialize_pem().map_err(|e| {
        return Error::new(ErrorKind::Other, format!("failed to serialize_pem {}", e));
    })?;
    // ref. "crypto/tls.parsePrivateKey"
    // ref. "crypto/x509.MarshalPKCS8PrivateKey"
    let key_contents = cert.serialize_private_key_pem();

    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(cert_contents.as_bytes())?;
    info!("saved cert {}", cert_path);

    let mut key_file = File::create(key_path)?;
    key_file.write_all(key_contents.as_bytes())?;
    info!("saved key {}", key_path);

    Ok(())
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- cert::test_cert --exact --show-output
#[test]
fn test_cert() {
    use std::fs;
    use utils::random;
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

    generate(&key_path, &cert_path).unwrap();

    let key_contents = fs::read(key_path).unwrap();
    let key_contents = String::from_utf8(key_contents.to_vec()).unwrap();
    info!("key: {} bytes", key_contents.len());

    // openssl x509 -in [cert_path] -text -noout
    let cert_contents = fs::read(cert_path).unwrap();
    let cert_contents = String::from_utf8(cert_contents.to_vec()).unwrap();
    info!("cert: {} bytes", cert_contents.len());
}
