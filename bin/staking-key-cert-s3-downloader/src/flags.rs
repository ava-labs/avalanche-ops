/// Defines flag options.
pub struct Options {
    pub log_level: String,
    pub aws_region: String,
    pub s3_bucket: String,
    pub s3_key_tls_key: String,
    pub s3_key_tls_cert: String,
    pub kms_cmk_id: String,
    pub tls_key_path: String,
    pub tls_cert_path: String,
}
