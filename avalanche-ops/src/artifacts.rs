use rust_embed::RustEmbed;

pub fn prometheus_rules() -> prometheus_manager::Rules {
    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;

    let filters_raw = Asset::get("artifacts/default.metrics.rules.yaml").unwrap();
    let filters_raw = std::str::from_utf8(filters_raw.data.as_ref()).unwrap();
    serde_yaml::from_str(filters_raw).unwrap()
}
