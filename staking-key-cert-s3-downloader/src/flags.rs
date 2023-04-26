/// Defines flag options.
#[derive(Debug)]
pub struct Options {
    pub log_level: String,
    pub s3_region: String,
    pub s3_bucket: String,
    pub s3_key_tls_key: String,
    pub s3_key_tls_cert: String,
    pub kms_region: String,
    pub kms_key_id: String,
    pub aad_tag: String,
    pub tls_key_path: String,
    pub tls_cert_path: String,
}
