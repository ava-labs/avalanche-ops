/// Defines flag options.
pub struct Options {
    pub log_level: String,

    /// Set "true" to run "avalanched" without downloading any "avalancheup" spec dependencies.
    /// Used for CDK integration.
    pub use_default_config: bool,
    pub skip_publish_node_info: bool,
}
