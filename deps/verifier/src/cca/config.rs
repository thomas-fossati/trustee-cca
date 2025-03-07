// Copyright (c) 2025 Linaro Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const DEFAULT_CCA_CONFIG: &str = "/etc/coco-as/cca-config.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub local_verifier: Option<LocalVerifier>,
    pub remote_verifier: Option<RemoteVerifier>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RemoteVerifier {
    pub origin: String,
    pub ca_cert: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalVerifier {
    pub ta_store: String,
    pub rv_store: String,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to parse CCA config file: {0}")]
    JsonFileParse(#[source] serde_json::Error),
}

impl Default for Config {
    fn default() -> Config {
        Config {
            remote_verifier: None,
            local_verifier: None,
        }
    }
}

impl TryFrom<&Path> for Config {
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, Config>(file).map_err(ConfigError::JsonFileParse)
    }
}
