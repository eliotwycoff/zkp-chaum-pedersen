use lazy_static::lazy_static;
use serde::Deserialize;

lazy_static! {
    pub static ref SHARED: SharedConfig =
        SharedConfig::new().expect("Failed to initialize shared config");
}

#[derive(Deserialize)]
pub struct SharedConfig {
    pub auth_server_address: String,
}

impl SharedConfig {
    pub fn new() -> Result<Self, config::ConfigError> {
        let conf = config::Config::builder()
            .add_source(config::File::with_name("config/shared.toml"))
            .build()?;

        conf.try_deserialize()
    }
}
