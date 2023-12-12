use crate::config::error::ConfigResult;
use figment::value::{Uncased, UncasedStr};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use log::debug;
use miette::miette;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

pub use crate::config::config::*;

mod config;
mod error;

pub trait ConfigurationService {
    fn read(&self) -> Arc<MollieConfig>;
    fn update(&self, updater: &dyn Fn(&mut MollieConfig)) -> ConfigResult<Arc<MollieConfig>>;
}

pub struct FigmentConfigurationService {
    cache: RwLock<Option<Arc<MollieConfig>>>,
}

impl FigmentConfigurationService {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(None),
        }
    }

    fn config_path() -> PathBuf {
        let mut config_path = PathBuf::new();

        if cfg!(debug_assertions) {
            config_path.push("/tmp/.mol/conf.toml");
        } else {
            config_path.push(dirs::home_dir().unwrap());
            config_path.push(".mol/conf.toml");
        }

        config_path
    }

    fn map_env_variables(str: &UncasedStr) -> Uncased {
        match str {
            _ if str == "api_url" => "api.url".into(),
            _ if str == "api_key" => "auth.api_keys.live".into(),
            _ if str == "access_token" => "auth.access_code.token".into(),
            _ => str.as_str().replace("__", ".").into(),
        }
    }

    fn create_diagnostic(error: figment::Error) -> miette::Error {
        let source = error
            .metadata
            .and_then(|metadata| metadata.source)
            .map(|source| source.to_string());

        let path = error.path.join(".");

        let help = if let Some(source) = source {
            format!(
                "A configuration value loaded from {} is invalid. Check the value at '{}'",
                source, path,
            )
        } else {
            format!(
                "A configuration value that was passed as an environmental variable was invalid. Check the value at '{}'",
                path,
            )
        };

        miette!(
            code = "config:load",
            severity = miette::Severity::Error,
            help = help,
            "{}",
            error.kind,
        )
    }

    fn read_figment_configuration() -> MollieConfig {
        // Figment's test mode can only read config files from the current working directory.
        let figment = if cfg!(test) {
            Figment::new().merge(Toml::file("conf.toml"))
        } else {
            Figment::new().merge(Toml::file(Self::config_path()))
        };

        figment
            .merge(Env::prefixed("MOLLIE_").map(Self::map_env_variables))
            .extract::<MollieConfig>()
            .map_err(Self::create_diagnostic)
            .expect("Failed to load configuration, error code:")
    }
}

impl ConfigurationService for FigmentConfigurationService {
    fn read(&self) -> Arc<MollieConfig> {
        // First, we try to read the configuration from the cache. If it's not there, we'll need to
        // re-acquire the lock as a write-lock for initialization.
        {
            let cache = self.cache.read().expect("Configuration lock is poisoned");

            if let Some(config) = &*cache {
                return config.clone();
            }
        }

        let mut cache = self.cache.write().expect("Configuration lock is poisoned");

        let new_config = Arc::new(Self::read_figment_configuration());
        *cache = Some(new_config.clone());
        new_config
    }

    fn update(&self, updater: &dyn Fn(&mut MollieConfig)) -> ConfigResult<Arc<MollieConfig>> {
        let mut cache = self.cache.write().expect("Configuration lock is poisoned");
        let mut new_config = cache
            .as_deref()
            .cloned()
            .unwrap_or_else(Self::read_figment_configuration);

        updater(&mut new_config);
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let new_config_contents = toml::to_string_pretty(&new_config)?;
        fs::write(&path, new_config_contents)?;

        let new_config = Arc::new(new_config);
        *cache = Some(new_config.clone());

        debug!("Saved configuration file to {}", path.to_string_lossy());

        Ok(new_config)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mollie_api::auth;
    use url::Url;

    #[test]
    fn should_read_config() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file(
                "conf.toml",
                r#"
                    [api]
                    url = "https://test.com/"
                    
                    [auth.access_code]
                    token = "access_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx123"
                    
                    [auth.api_keys]
                    live = "live_xxxxxxxxxxxxxxxxxxxxxxxxxxx123"
                    test = "test_xxxxxxxxxxxxxxxxxxxxxxxxxxx456"
                    
                    [auth.connect]
                    client_id = "client_id"
                    client_secret = "client_secret"
                    refresh_token = "refresh_token"
                    access_token = "access_token"
                "#,
            )?;

            let service = FigmentConfigurationService::new();
            let config = service.read();

            assert_eq!(
                config.as_ref(),
                &MollieConfig {
                    api: ApiConfig {
                        url: Url::parse("https://test.com/").unwrap(),
                    },
                    auth: AuthConfig {
                        access_code: Some(AccessCodeConfig {
                            token: auth::AccessCode {
                                value: "access_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx123"
                                    .to_string()
                            },
                        }),
                        api_keys: Some(ApiKeysConfig {
                            live: Some(auth::ApiKey {
                                mode: auth::ApiKeyMode::Live,
                                value: "live_xxxxxxxxxxxxxxxxxxxxxxxxxxx123".to_string(),
                            }),
                            test: Some(auth::ApiKey {
                                mode: auth::ApiKeyMode::Test,
                                value: "test_xxxxxxxxxxxxxxxxxxxxxxxxxxx456".to_string(),
                            }),
                        }),
                        connect: Some(ConnectConfig {
                            client_id: "client_id".to_string(),
                            client_secret: "client_secret".to_string(),
                            refresh_token: Some("refresh_token".to_string()),
                            access_token: Some("access_token".to_string()),
                        }),
                    },
                }
            );

            Ok(())
        });
    }

    #[test]
    fn should_use_env_overrides() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file(
                "conf.toml",
                r#"
                    [api]
                    url = "https://test.com/"
                "#,
            )?;

            jail.set_env("MOLLIE_API__URL", "https://env.com/");
            jail.set_env(
                "MOLLIE_AUTH__ACCESS_CODE__TOKEN",
                "access_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx123",
            );
            jail.set_env(
                "MOLLIE_AUTH__API_KEYS__LIVE",
                "live_xxxxxxxxxxxxxxxxxxxxxxxxxxx123",
            );

            let service = FigmentConfigurationService::new();
            let config = service.read();

            assert_eq!(
                config.as_ref(),
                &MollieConfig {
                    api: ApiConfig {
                        url: Url::parse("https://env.com/").unwrap(),
                    },
                    auth: AuthConfig {
                        api_keys: Some(ApiKeysConfig {
                            live: Some(auth::ApiKey {
                                mode: auth::ApiKeyMode::Live,
                                value: "live_xxxxxxxxxxxxxxxxxxxxxxxxxxx123".to_string(),
                            }),
                            test: None,
                        }),
                        access_code: Some(AccessCodeConfig {
                            token: auth::AccessCode {
                                value: "access_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx123"
                                    .to_string()
                            },
                        }),
                        connect: None,
                    }
                }
            );

            Ok(())
        });
    }

    #[test]
    fn should_use_env_variable_shorthands() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file(
                "conf.toml",
                r#"
                    [api]
                    url = "https://test.com/"
                "#,
            )?;

            jail.set_env("MOLLIE_API_URL", "https://env.com/");
            jail.set_env(
                "MOLLIE_ACCESS_TOKEN",
                "access_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx123",
            );
            jail.set_env("MOLLIE_API_KEY", "live_xxxxxxxxxxxxxxxxxxxxxxxxxxx123");

            let service = FigmentConfigurationService::new();
            let config = service.read();

            assert_eq!(
                config.as_ref(),
                &MollieConfig {
                    api: ApiConfig {
                        url: Url::parse("https://env.com/").unwrap(),
                    },
                    auth: AuthConfig {
                        api_keys: Some(ApiKeysConfig {
                            live: Some(auth::ApiKey {
                                mode: auth::ApiKeyMode::Live,
                                value: "live_xxxxxxxxxxxxxxxxxxxxxxxxxxx123".to_string(),
                            }),
                            test: None,
                        }),
                        access_code: Some(AccessCodeConfig {
                            token: auth::AccessCode {
                                value: "access_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx123"
                                    .to_string()
                            },
                        }),
                        connect: None,
                    }
                }
            );

            Ok(())
        });
    }
}
