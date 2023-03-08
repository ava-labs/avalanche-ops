/// Defines flag options.
#[derive(Debug)]
pub struct Options {
    pub log_level: String,

    /// Set "true" to run "avalanched" without downloading any "avalancheup" spec dependencies.
    /// Used for CDK integration.
    pub use_default_config: bool,

    /// The node information is published regardless of anchor/non-anchor.
    /// This is set "true" iff the node wishes to publish it periodically.
    /// Otherwise, publish only once until success!
    /// Might be useful to publish ready heartbeats to S3 in the future.
    pub publish_periodic_node_info: bool,
}
