/// Defines flag options.
#[derive(Debug)]
pub struct Options {
    pub log_level: String,
    pub s3_region: String,
    pub s3_bucket: String,
    pub s3_key: String,
    pub kms_region: String,
    pub kms_key_id: String,
    pub aad_tag: String,
    pub key_path: String,
}
