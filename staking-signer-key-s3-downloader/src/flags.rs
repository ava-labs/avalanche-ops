/// Defines flag options.
#[derive(Debug)]
pub struct Options {
    pub log_level: String,
    pub region: String,
    pub s3_bucket: String,
    pub s3_key: String,
    pub kms_key_id: String,
    pub aad_tag: String,
    pub key_path: String,
}
