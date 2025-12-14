// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::{borrow::Cow, collections::HashMap, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

macro_rules! skip_fmt {
    ($($i:item)*) => { $($i)* };
}

pub type StaticCow = Cow<'static, str>;
pub type MaybeIPList = Option<HashMap<IpVersion, Vec<ListEntry>>>;

pub fn resolve_fragment(user_path: Option<String>, filename: &str) -> Result<PathBuf> {
    if let Some(path) = user_path {
        return Ok(PathBuf::from(path));
    }

    const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
    let search_paths = [
        // Current Working Directory
        PathBuf::from(filename),
        // Standard Linux Config Location
        PathBuf::from(format!("/etc/{}/{}", PACKAGE_NAME, filename)),
        // BSD / Local Config Location
        PathBuf::from(format!("/usr/local/etc/{}/{}", PACKAGE_NAME, filename)),
    ];

    search_paths
        .into_iter()
        .find(|path| path.exists())
        .inspect(|path| {
            let abs_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            debug!("Found default {} at {}", filename, abs_path.display());
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not find '{}'. Checked current directory, /etc/{}/, and /usr/local/etc/{}/.",
                filename,
                PACKAGE_NAME,
                PACKAGE_NAME
            )
        })
}

fn get_default_interface() -> Option<StaticCow> {
    fs::read_to_string("/proc/net/route")
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let first = parts.next()?;
            if parts.next()? == "00000000" {
                Some(Cow::Owned(first.to_owned()))
            } else {
                None
            }
        })
}

/// Serde deserializer for single or multiple values
fn deserialize_one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(val) => Ok(vec![val]),
        OneOrMany::Many(vec) => Ok(vec),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListEntry {
    /// Supports the legacy format: - "<https://example.com/list.ip>"
    Simple(String),
    /// Supports the new format:    - { `url`: "...", `min_prefix`: 24 }
    Detailed { url: String, min_prefix: Option<u8> },
}

// Helper to extract data regardless of format
impl ListEntry {
    pub fn as_parts(&self) -> (&str, Option<u8>) {
        match self {
            Self::Simple(s) => (s, None),
            Self::Detailed { url, min_prefix } => (url, *min_prefix),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    #[serde(rename = "v4")]
    V4,
    #[serde(rename = "v6")]
    V6,
}

impl IpVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

skip_fmt! {
    const fn default_true() -> bool { true }
    const fn default_min_prefix_v4() -> u8 { 8 }
    const fn default_min_prefix_v6() -> u8 { 16 }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Ipv4Conf {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_min_prefix_v4")]
    pub min_prefix: u8,
}

impl Default for Ipv4Conf {
    fn default() -> Self {
        Self {
            enabled: true,
            min_prefix: default_min_prefix_v4(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Ipv6Conf {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_min_prefix_v6")]
    pub min_prefix: u8,
}

impl Default for Ipv6Conf {
    fn default() -> Self {
        Self {
            enabled: true,
            min_prefix: default_min_prefix_v6(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct IpConfigs {
    #[serde(default)]
    pub v4: Ipv4Conf,
    #[serde(default)]
    pub v6: Ipv6Conf,
}

impl IpConfigs {
    pub fn get_active(&self) -> impl Iterator<Item = IpVersion> {
        let v4 = self.v4.enabled.then_some(IpVersion::V4);
        let v6 = self.v6.enabled.then_some(IpVersion::V6);
        v4.into_iter().chain(v6)
    }
}

skip_fmt! {
    const fn default_accept() -> StaticCow { Cow::Borrowed("accept") }
    const fn default_drop() -> StaticCow { Cow::Borrowed("drop") }
    const fn default_log_enabled() -> bool { true }
    const fn default_log_ratelimiting() -> bool { true }
    const fn default_log_rate() -> u64 { 10 }
    const fn default_log_burst() -> u64 { 5 }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct LogConfig {
    #[serde(default = "default_log_enabled")]
    pub enabled: bool,
    #[serde(default = "default_log_enabled")]
    pub ratelimiting: bool,
    #[serde(default = "default_log_rate")]
    pub rate: u64,
    #[serde(default = "default_log_burst")]
    pub burst: u64,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enabled: default_log_enabled(),
            ratelimiting: default_log_ratelimiting(),
            rate: default_log_rate(),
            burst: default_log_burst(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AsnSources {
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub v4: Vec<StaticCow>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub v6: Vec<StaticCow>,
}

impl Default for AsnSources {
    fn default() -> Self {
        Self {
            v4: vec![Cow::Borrowed(
                "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{asn}/ipv4-aggregated.txt",
            )],
            v6: vec![Cow::Borrowed(
                "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{asn}/ipv6-aggregated.txt",
            )],
        }
    }
}

impl AsnSources {
    pub fn get(&self, version: IpVersion) -> &[StaticCow] {
        match version {
            IpVersion::V4 => &self.v4,
            IpVersion::V6 => &self.v6,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CountrySources {
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub v4: Vec<StaticCow>,
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub v6: Vec<StaticCow>,
}

impl Default for CountrySources {
    fn default() -> Self {
        Self {
            v4: vec![Cow::Borrowed(
                "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{country}.cidr",
            )],
            v6: vec![Cow::Borrowed(
                "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/{country}.cidr",
            )],
        }
    }
}

impl CountrySources {
    pub fn get(&self, version: IpVersion) -> &[StaticCow] {
        match version {
            IpVersion::V4 => &self.v4,
            IpVersion::V6 => &self.v6,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Sources {
    #[serde(default)]
    pub asn: AsnSources,
    #[serde(default)]
    pub country: CountrySources,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SetNames {
    pub whitelist: StaticCow,
    pub blacklist: StaticCow,
    pub abuselist: StaticCow,
    pub country: StaticCow,
}

impl Default for SetNames {
    fn default() -> Self {
        Self {
            whitelist: Cow::Borrowed("whitelist"),
            blacklist: Cow::Borrowed("blacklist"),
            abuselist: Cow::Borrowed("abuselist"),
            country: Cow::Borrowed("country"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(rename = "NET", default)]
    pub net: IpConfigs,
    #[serde(rename = "DEFAULT_POLICY", default = "default_accept")]
    pub default_policy: StaticCow,
    #[serde(rename = "BLOCK_POLICY", default = "default_drop")]
    pub block_policy: StaticCow,
    #[serde(
        rename = "IIFNAME",
        default,
        deserialize_with = "deserialize_one_or_many"
    )]
    pub iifname: Vec<StaticCow>,
    #[serde(rename = "SET_NAMES", default)]
    pub set_names: SetNames,
    #[serde(rename = "LOGGING", default)]
    pub logging: LogConfig,
    #[serde(rename = "SOURCES", default)]
    pub sources: Sources,
    #[serde(rename = "WHITELIST")]
    pub whitelist: MaybeIPList,
    #[serde(rename = "BLACKLIST")]
    pub blacklist: MaybeIPList,
    #[serde(rename = "ABUSELIST")]
    pub abuselist: MaybeIPList,
    #[serde(rename = "COUNTRY_LIST")]
    pub country_list: Option<Vec<String>>,
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        info!("Loading config from: {}", path.display());
        let content = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path.display()))?;
        let mut config: Self =
            serde_saphyr::from_str(&content).context("Failed to parse YAML configuration")?;

        if !config.net.v4.enabled && !config.net.v6.enabled {
            anyhow::bail!("At least one IP version (v4 or v6) must be enabled");
        }

        if config.iifname.is_empty() {
            if let Some(def) = get_default_interface() {
                info!("Determined default interface: {}", def);
                config.iifname.push(def);
            } else {
                warn!("No interface specified and no default route found. Using fallback 'eth0'");
                config.iifname.push(Cow::Borrowed("eth0"));
            }
        }
        Ok(config)
    }
}
