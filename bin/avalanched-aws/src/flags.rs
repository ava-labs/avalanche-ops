/// Defines flag options.
pub struct Options {
    pub log_level: String,

    /// Set "true" to run "avalanched" without any "avalancheup" spec dependencies.
    /// Used for CDK integration.
    pub lite_mode: bool,
}
