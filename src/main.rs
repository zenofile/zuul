mod threadpool;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Output},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;

use crate::threadpool::ThreadPool;

#[derive(Parser, Debug)]
#[command(name = "nft-void")]
#[command(about = "Script to block IPs in nftables by country and abuselists", long_about = None)]
struct Cli {
    #[command(subcommand)]
    action: Action,

    /// Path to configuration file
    #[arg(required = true, short, long)]
    config: PathBuf,

    /// Path to template file
    #[arg(required = true, short, long)]
    template: PathBuf,

    /// Increase verbosity level (-v, -vv, -vvv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Number of worker threads
    #[arg(short = 'w', long, default_value_t = 4)]
    threads: usize,

    /// Timeout for requests in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Perform a dry-run without making actual changes
    #[arg(short = 'n', long)]
    dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Start nft-void and create firewall rules
    Start {
        #[arg(short = 'o', long = "stdout")]
        print_stdout: bool,
    },
    /// Stop nft-void and remove firewall rules
    Stop,
    /// Restart nft-void (stop then start)
    Restart,
    /// Update lists
    Refresh {
        #[arg(short = 'o', long = "stdout")]
        print_stdout: bool,
    },
    /// Display current configuration
    Config,
}

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(rename = "IP_VERSIONS")]
    ip_versions: IpVersions,

    #[serde(rename = "DEFAULT_POLICY", default = "default_accept")]
    default_policy: String,

    #[serde(rename = "SET_NAMES", default)]
    set_names: SetNames,

    #[serde(rename = "BLOCK_POLICY", default = "default_drop")]
    block_policy: String,

    #[serde(rename = "IIFNAME", default = "get_default_interface")]
    iifname: Option<String>,

    #[serde(rename = "WHITELIST")]
    whitelist: Option<HashMap<IpVersion, Vec<String>>>,

    #[serde(rename = "BLACKLIST")]
    blacklist: Option<HashMap<IpVersion, Vec<String>>>,

    #[serde(rename = "ABUSELIST")]
    abuselist: Option<HashMap<IpVersion, Vec<String>>>,

    #[serde(rename = "COUNTRY_LIST")]
    country_list: Option<Vec<String>>,

    #[serde(rename = "ASN_URLS")]
    asn_urls: Option<HashMap<IpVersion, String>>,
}

#[derive(Debug)]
struct AppContext {
    config: Config,
    template: PathBuf,
    timeout: u64,
    threads: usize,
    dry_run: bool,
    print_stdout: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SetNames {
    whitelist: String,
    blacklist: String,
    abuselist: String,
    country: String,
}

impl Default for SetNames {
    fn default() -> Self {
        Self {
            whitelist: String::from("whitelist"),
            blacklist: String::from("blacklist"),
            abuselist: String::from("abuselist"),
            country: String::from("country"),
        }
    }
}

fn default_accept() -> String {
    String::from("accept")
}

fn default_drop() -> String {
    String::from("drop")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum IpVersion {
    #[serde(rename = "v4")]
    V4,
    #[serde(rename = "v6")]
    V6,
}

impl IpVersion {
    const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Deserialize)]
struct IpVersions {
    v4: bool,
    v6: bool,
}

impl IpVersions {
    fn get_active(&self) -> impl Iterator<Item = IpVersion> {
        let v4 = self.v4.then_some(IpVersion::V4);
        let v6 = self.v6.then_some(IpVersion::V6);
        v4.into_iter().chain(v6)
    }
}

impl std::fmt::Display for IpVersions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.get_active();

        match iter.next() {
            None => write!(f, "none"),
            Some(first) => {
                write!(f, "{}", first)?;
                for version in iter {
                    write!(f, ", {}", version)?;
                }
                Ok(())
            }
        }
    }
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        info!("Loading config from: {}", path.display());
        let content = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path.display()))?;

        let config: Self =
            serde_saphyr::from_str(&content).context("Failed to parse YAML configuration")?;

        if !config.ip_versions.v4 && !config.ip_versions.v6 {
            anyhow::bail!("At least one IP version (v4 or v6) must be enabled");
        }

        Ok(config)
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "IP_VERSIONS: v4={}, v6={}",
            self.ip_versions.v4, self.ip_versions.v6
        )?;
        writeln!(f, "SET_NAMES: {:?}", self.set_names)?;
        writeln!(f, "DEFAULT_POLICY: {}", self.default_policy)?;
        writeln!(f, "BLOCK_POLICY: {}", self.block_policy)?;
        writeln!(f, "IIFNAME: {:?}", self.iifname)?;
        writeln!(f, "WHITELIST: {:?}", self.whitelist)?;
        writeln!(f, "BLACKLIST: {:?}", self.blacklist)?;
        writeln!(f, "ABUSELIST: {:?}", self.abuselist)?;
        writeln!(f, "COUNTRY_LIST: {:?}", self.country_list)?;
        Ok(())
    }
}

#[derive(Debug)]
struct IpSets {
    v4_sets: HashMap<String, BTreeSet<Ipv4Net>>,
    v6_sets: HashMap<String, BTreeSet<Ipv6Net>>,
}

impl IpSets {
    fn new() -> Self {
        Self {
            v4_sets: HashMap::new(),
            v6_sets: HashMap::new(),
        }
    }

    #[inline]
    fn strip_comment_and_trim(line: &str) -> &str {
        let result = line.split_once('#').map_or(line, |(before, _)| before);
        result.trim()
    }

    fn insert_v4(&mut self, set_name: String, ips: Vec<String>) {
        let mut parsed_ips = BTreeSet::new();
        let mut invalid_count = 0;

        for ip_str in ips {
            let cleaned = Self::strip_comment_and_trim(&ip_str);
            if cleaned.is_empty() {
                continue;
            }

            match <Ipv4Net as std::str::FromStr>::from_str(cleaned) {
                Ok(net) => {
                    parsed_ips.insert(net);
                }
                Err(_) => {
                    if let Ok(addr) = cleaned.parse::<std::net::Ipv4Addr>() {
                        parsed_ips.insert(Ipv4Net::new(addr, 32).unwrap());
                    } else {
                        invalid_count += 1;
                        debug!("Invalid IPv4 address/network: {}", cleaned);
                    }
                }
            }
        }

        if invalid_count > 0 {
            warn!(
                "Skipped {} invalid IPv4 entries for set {}",
                invalid_count, set_name
            );
        }

        info!(
            "Set {}: {} unique IPv4 networks (deduplicated from {} entries)",
            set_name,
            parsed_ips.len(),
            parsed_ips.len() + invalid_count
        );

        self.v4_sets.insert(set_name, parsed_ips);
    }

    fn insert_v6(&mut self, set_name: String, ips: Vec<String>) {
        let mut parsed_ips = BTreeSet::new();
        let mut invalid_count = 0;

        for ip_str in ips {
            let cleaned = Self::strip_comment_and_trim(&ip_str);
            if cleaned.is_empty() {
                continue;
            }

            match <Ipv6Net as std::str::FromStr>::from_str(cleaned) {
                Ok(net) => {
                    parsed_ips.insert(net);
                }
                Err(_) => {
                    if let Ok(addr) = cleaned.parse::<std::net::Ipv6Addr>() {
                        parsed_ips.insert(Ipv6Net::new(addr, 128).unwrap());
                    } else {
                        invalid_count += 1;
                        debug!("Invalid IPv6 address/network: {}", cleaned);
                    }
                }
            }
        }

        if invalid_count > 0 {
            warn!(
                "Skipped {} invalid IPv6 entries for set {}",
                invalid_count, set_name
            );
        }

        info!(
            "Set {}: {} unique IPv6 networks (deduplicated from {} entries)",
            set_name,
            parsed_ips.len(),
            parsed_ips.len() + invalid_count
        );

        self.v6_sets.insert(set_name, parsed_ips);
    }

    fn get_v4_formatted(&self, set_name: &str) -> Option<String> {
        self.v4_sets.get(set_name).map(|nets| {
            nets.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",\n                ")
        })
    }

    fn get_v6_formatted(&self, set_name: &str) -> Option<String> {
        self.v6_sets.get(set_name).map(|nets| {
            nets.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",\n                ")
        })
    }
}

#[derive(Debug, Clone)]
struct DownloadJob {
    url: String,
}

#[derive(Debug)]
struct DownloadResult {
    url: String,
    content: Result<String>,
}

// Convenience constructor for downloads
impl ThreadPool<DownloadJob, DownloadResult> {
    // Convenience constructor for downloads
    fn downloader(size: usize, timeout: u64) -> Self {
        Self::new(
            size.try_into().expect("Pool size must be > 0"),
            move |job| download_url(timeout, job),
        )
    }
}

fn download_url(timeout: u64, job: DownloadJob) -> DownloadResult {
    let content = (|| -> Result<String> {
        let mut dst = Vec::new();
        let mut easy = curl::easy::Easy::new();

        easy.url(&job.url)
            .context(format!("Failed to set URL: {}", job.url))?;
        easy.timeout(std::time::Duration::from_secs(timeout))
            .context("Failed to set timeout")?;
        easy.useragent("Mozilla/5.0 (compatible; nft-void/0.1.0)")
            .context("Failed to set user agent")?;
        easy.follow_location(true)
            .context("Failed to enable follow location")?;

        {
            let mut transfer = easy.transfer();
            transfer
                .write_function(|data| {
                    dst.extend_from_slice(data);
                    Ok(data.len())
                })
                .context("Failed to set write function")?;

            transfer
                .perform()
                .context(format!("Failed to download: {}", job.url))?;
        }

        let response_code = easy
            .response_code()
            .context("Failed to get response code")?;
        if !(200..300).contains(&response_code) {
            anyhow::bail!("HTTP request failed with status code: {}", response_code);
        }

        let text = String::from_utf8(dst).context("Failed to parse response body as UTF-8")?;
        debug!("Got {} bytes of data from {}", text.len(), job.url);

        Ok(text)
    })();

    DownloadResult {
        url: job.url,
        content,
    }
}

fn download_files_aggregated(
    pool: &ThreadPool<DownloadJob, DownloadResult>,
    urls: Vec<String>,
) -> Vec<String> {
    use kanal::unbounded;

    if urls.is_empty() {
        return Vec::new();
    }

    let (result_sender, result_receiver) = unbounded();

    let num_jobs = urls.len();
    for url in urls {
        let job = DownloadJob { url };
        if let Err(e) = pool.execute(job, result_sender.clone()) {
            error!("Failed to queue download job: {}", e);
        }
    }

    drop(result_sender);

    let mut aggregated = Vec::with_capacity(4096);
    let mut received = 0;
    while received < num_jobs {
        if let Ok(result) = result_receiver.recv() {
            received += 1;
            match result.content {
                Ok(text) => {
                    let lines = text.lines().map(str::trim).filter(|s| !s.is_empty());

                    let start_len = aggregated.len();
                    aggregated.extend(lines.map(String::from));

                    info!(
                        "Downloaded {} lines from {}",
                        aggregated.len() - start_len,
                        result.url
                    );
                }
                Err(e) => {
                    warn!("Failed to download {}: {}", result.url, e);
                }
            }
        }
    }

    aggregated
}

fn get_abuselist(
    pool: &ThreadPool<DownloadJob, DownloadResult>,
    abuselist: &[String],
    ip_version: IpVersion,
    asn_url_template: Option<&str>,
) -> Vec<String> {
    let mut urls = Vec::new();
    let mut asn_urls = Vec::new();

    for entry in abuselist {
        let trimmed = entry.trim();

        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(trimmed.to_owned());
        } else if trimmed.to_uppercase().starts_with("AS") {
            let digits = &trimmed[2..];

            if digits.chars().all(|c| c.is_ascii_digit()) && !digits.is_empty() {
                info!("Processing ASN entry: AS{} for {}", digits, ip_version);

                let asn_url = asn_url_template.map_or_else(|| match ip_version {
                        IpVersion::V4 => format!(
                            "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{}/ipv4-aggregated.txt",
                            digits
                        ),
                        IpVersion::V6 => format!(
                            "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{}/ipv6-aggregated.txt",
                            digits
                        ),
                    }, |template| template.replace("{asn}", digits));

                asn_urls.push(asn_url);
            } else {
                warn!(
                    "Invalid ASN format (must be AS followed by digits): {}",
                    trimmed
                );
            }
        } else {
            warn!(
                "Ignoring entry with unknown format in abuselist: {}",
                trimmed
            );
        }
    }

    // Download all URLs (regular URLs and ASN-generated URLs)
    let mut all_urls = urls;
    all_urls.extend(asn_urls);

    download_files_aggregated(pool, all_urls)
}

fn get_country_ip_list(
    pool: &ThreadPool<DownloadJob, DownloadResult>,
    country_list: &[String],
    ip_version: IpVersion,
) -> Vec<String> {
    let urls: Vec<String> = country_list.iter().map(|country| {
        info!("Getting blocklist for country: {}", country);
        format!(
            "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ip{}/{}.cidr",
            ip_version,
            country.to_lowercase()
        )
    }).collect();

    download_files_aggregated(pool, urls)
}

fn generate_nftable(context: &AppContext, sets: &IpSets) -> Result<String> {
    let template_content =
        fs::read_to_string(&context.template).context("Failed to read template file")?;

    let mut env = minijinja::Environment::new();
    env.add_template("nft-void", &template_content)?;
    let template = env.get_template("nft-void")?;

    let mut set_data = HashMap::new();

    let config = &context.config;
    for ip_version in config.ip_versions.get_active() {
        let (
            whitelist_key,
            blacklist_key,
            abuselist_key,
            country_key,
            whitelist_set,
            blacklist_set,
            abuselist_set,
            country_set,
        ) = (
            format!("{}_{}", config.set_names.whitelist, ip_version),
            format!("{}_{}", config.set_names.blacklist, ip_version),
            format!("{}_{}", config.set_names.abuselist, ip_version),
            format!("{}_{}", config.set_names.country, ip_version),
            format!("{}_{}", config.set_names.whitelist, ip_version),
            format!("{}_{}", config.set_names.blacklist, ip_version),
            format!("{}_{}", config.set_names.abuselist, ip_version),
            format!("{}_{}", config.set_names.country, ip_version),
        );

        match ip_version {
            IpVersion::V4 => {
                set_data.insert(
                    whitelist_key,
                    sets.get_v4_formatted(&whitelist_set).unwrap_or_default(),
                );
                set_data.insert(
                    blacklist_key,
                    sets.get_v4_formatted(&blacklist_set).unwrap_or_default(),
                );
                set_data.insert(
                    abuselist_key,
                    sets.get_v4_formatted(&abuselist_set).unwrap_or_default(),
                );
                set_data.insert(
                    country_key,
                    sets.get_v4_formatted(&country_set).unwrap_or_default(),
                );
            }
            IpVersion::V6 => {
                set_data.insert(
                    whitelist_key,
                    sets.get_v6_formatted(&whitelist_set).unwrap_or_default(),
                );
                set_data.insert(
                    blacklist_key,
                    sets.get_v6_formatted(&blacklist_set).unwrap_or_default(),
                );
                set_data.insert(
                    abuselist_key,
                    sets.get_v6_formatted(&abuselist_set).unwrap_or_default(),
                );
                set_data.insert(
                    country_key,
                    sets.get_v6_formatted(&country_set).unwrap_or_default(),
                );
            }
        }
    }

    // Render template with all context
    use minijinja::context;
    let rules = template.render(context! {
        iifname => config.iifname.as_deref().unwrap(),
        default_policy => &config.default_policy,
        block_policy => &config.block_policy,
        set_names => &config.set_names,
        sets => set_data,
        ip_versions => context! {
            v4 => config.ip_versions.v4,
            v6 => config.ip_versions.v6,
        },
    })?;

    Ok(rules)
}

fn collect_ip_sets(context: &AppContext) -> IpSets {
    let config = &context.config;
    let mut sets = IpSets::new();
    let pool = ThreadPool::downloader(context.threads, context.timeout);

    for ip_version in config.ip_versions.get_active() {
        info!("Collecting IP sets for {}", ip_version);

        // Process whitelist
        if let Some(whitelist) = &config.whitelist
            && let Some(ips) = whitelist.get(&ip_version)
        {
            info!(
                "Processing whitelist for {}: {} entries",
                ip_version,
                ips.len()
            );
            let set_name = format!("{}_{}", config.set_names.whitelist, ip_version);
            match ip_version {
                IpVersion::V4 => sets.insert_v4(set_name, ips.clone()),
                IpVersion::V6 => sets.insert_v6(set_name, ips.clone()),
            }
        }

        // Process blacklist
        if let Some(blacklist) = &config.blacklist
            && let Some(ips) = blacklist.get(&ip_version)
        {
            info!(
                "Processing blacklist for {}: {} entries",
                ip_version,
                ips.len()
            );
            let set_name = format!("{}_{}", config.set_names.blacklist, ip_version);
            match ip_version {
                IpVersion::V4 => sets.insert_v4(set_name, ips.clone()),
                IpVersion::V6 => sets.insert_v6(set_name, ips.clone()),
            }
        }

        // Process abuselist
        if let Some(abuselist) = &config.abuselist
            && let Some(urls) = abuselist.get(&ip_version)
        {
            let asn_template = config
                .asn_urls
                .as_ref()
                .and_then(|templates| templates.get(&ip_version))
                .map(String::as_str);
            let ip_list = get_abuselist(&pool, urls, ip_version, asn_template);
            info!(
                "Processed abuselist for {}: {} entries",
                ip_version,
                ip_list.len()
            );
            let set_name = format!("{}_{}", config.set_names.abuselist, ip_version);
            match ip_version {
                IpVersion::V4 => sets.insert_v4(set_name, ip_list),
                IpVersion::V6 => sets.insert_v6(set_name, ip_list),
            }
        }

        // Process country list
        if let Some(country_list) = &config.country_list
            && !country_list.is_empty()
        {
            let ip_list = get_country_ip_list(&pool, country_list, ip_version);
            info!(
                "Processed country list for {}: {} entries",
                ip_version,
                ip_list.len()
            );
            let set_name = format!("{}_{}", config.set_names.country, ip_version);
            match ip_version {
                IpVersion::V4 => sets.insert_v4(set_name, ip_list),
                IpVersion::V6 => sets.insert_v6(set_name, ip_list),
            }
        }
    }

    sets
}

fn get_default_interface() -> Option<String> {
    let contents = fs::read_to_string("/proc/net/route").ok()?;
    for line in contents.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<&str>>();
        if fields.len() >= 2 && fields[1] == "00000000" {
            return Some(fields[0].to_owned());
        }
    }
    None
}

fn run_nft_cli(args: &[&str], dry_run: bool) -> Result<Output> {
    if dry_run {
        debug!("Mocking nft command: nft {}", args.join(" "));
        let mock_status =
            <std::process::ExitStatus as std::os::unix::process::ExitStatusExt>::from_raw(0);
        return Ok(Output {
            status: mock_status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
    }
    info!("Executing nft command: nft {}", args.join(" "));
    let output = Command::new("nft")
        .args(args)
        .output()
        .context("Failed to execute nft command")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("nft command failed: {}", stderr);
        return Err(anyhow::anyhow!("nft execution error: {stderr}"));
    }
    Ok(output)
}

fn run_nft_stdin(rules: &str, dry_run: bool) -> Result<Output> {
    use std::process::Stdio;

    if dry_run {
        debug!("Mocking nft command: nft -f -");
        let mock_status =
            <std::process::ExitStatus as std::os::unix::process::ExitStatusExt>::from_raw(0);
        return Ok(Output {
            status: mock_status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
    }
    info!("Executing nft command: nft -f -");

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn nft command")?;

    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    stdin
        .write_all(rules.as_bytes())
        .context("Failed to write rules to nft stdin")?;

    let output = child
        .wait_with_output()
        .context("Failed to wait on nft command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("nft command failed: {}", stderr);
        return Err(anyhow::anyhow!("nft execution error: {stderr}"));
    }
    Ok(output)
}

fn write_to_stdout(buf: &str) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(buf.as_bytes())?;
    Ok(())
}

fn start(context: &AppContext) -> Result<()> {
    info!("Starting nft-void");
    let sets = collect_ip_sets(context);
    let rules = generate_nftable(context, &sets)?;

    if context.print_stdout {
        write_to_stdout(&rules)?;
    }
    run_nft_stdin(&rules, context.dry_run)?;

    let (mut total_v4, mut total_v6) = (0usize, 0usize);

    for (setname, ips) in &sets.v4_sets {
        total_v4 += ips.len();
        info!("Set IPv4 {}: {} entries", setname, ips.len());
    }
    for (setname, ips) in &sets.v6_sets {
        total_v6 += ips.len();
        info!("Set IPv6 {}: {} entries", setname, ips.len());
    }
    info!(
        "Total entries IPv4: {} IPv6: {} total: {}",
        total_v4,
        total_v6,
        total_v4 + total_v6
    );

    Ok(())
}

fn stop() -> Result<()> {
    info!("Stopping nft-void");
    run_nft_cli(&["delete", "table", "netdev", "blackhole"], false)?;
    info!("Successfully deleted nftables table 'netdev blackhole'");
    Ok(())
}

fn refresh(context: &AppContext) -> Result<()> {
    use std::fmt::Write as _;

    info!("Reloading abuselist and country lists");

    let mut flush_commands = String::with_capacity(512);

    let config = &context.config;
    for ip_version in config.ip_versions.get_active() {
        let abuselist_set = format!("{}_{}", config.set_names.abuselist, ip_version);
        let country_set = format!("{}_{}", config.set_names.country, ip_version);

        writeln!(
            flush_commands,
            "flush set netdev blackhole {}",
            abuselist_set
        )?;
        writeln!(flush_commands, "flush set netdev blackhole {}", country_set)?;
    }

    if context.print_stdout {
        write_to_stdout(&flush_commands)?;
    }
    run_nft_stdin(&flush_commands, context.dry_run)?;
    info!("Flushed ABUSELIST and COUNTRY_LIST sets");

    let sets = collect_ip_sets(context);

    let mut add_commands = String::with_capacity(4096);

    for ip_version in config.ip_versions.get_active() {
        let abuselist_set = format!("{}_{}", config.set_names.abuselist, ip_version);
        let country_set = format!("{}_{}", config.set_names.country, ip_version);

        let abuselist_elements = match ip_version {
            IpVersion::V4 => sets.get_v4_formatted(&abuselist_set),
            IpVersion::V6 => sets.get_v6_formatted(&abuselist_set),
        };

        if let Some(elements) = abuselist_elements
            && !elements.is_empty()
        {
            writeln!(
                add_commands,
                "add element netdev blackhole {} {{ {} }}",
                abuselist_set, elements
            )?;
        }

        let country_elements = match ip_version {
            IpVersion::V4 => sets.get_v4_formatted(&country_set),
            IpVersion::V6 => sets.get_v6_formatted(&country_set),
        };

        if let Some(elements) = country_elements
            && !elements.is_empty()
        {
            writeln!(
                add_commands,
                "add element netdev blackhole {} {{ {} }}",
                country_set, elements
            )?;
        }
    }

    if !add_commands.is_empty() {
        if context.print_stdout {
            write_to_stdout(&add_commands)?;
        }
        run_nft_stdin(&add_commands, context.dry_run)?;
    }

    let (mut total_v4, mut total_v6) = (0usize, 0usize);

    for (setname, ips) in &sets.v4_sets {
        total_v4 += ips.len();
        info!("Reloaded IPv4 set {}: {} entries", setname, ips.len());
    }

    for (setname, ips) in &sets.v6_sets {
        total_v6 += ips.len();
        info!("Reloaded IPv6 set {}: {} entries", setname, ips.len());
    }

    info!(
        "Reloaded total entries IPv4: {} IPv6: {} total: {}",
        total_v4,
        total_v6,
        total_v4 + total_v6
    );

    info!("Successfully reloaded ABUSELIST and COUNTRY_LIST sets");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    if std::env::var("JOURNAL_STREAM").is_ok() {
        let journald_layer = tracing_journald::layer().expect("Failed to connect to journald");

        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into()))
            .with(journald_layer)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into()),
            )
            .with_writer(std::io::stderr)
            .init();
    }

    let mut config = Config::load(&cli.config)?;

    if let Some(ref iifname) = config.iifname {
        info!("Using network interface: {}", iifname);
    } else {
        config.iifname = Some("eth0".to_owned());
        warn!("Using fallback interface eth0");
    }

    let print_stdout = match &cli.action {
        Action::Start { print_stdout } | Action::Refresh { print_stdout } => *print_stdout,
        _ => false,
    };
    if print_stdout {
        info!("Printing generated nftables to stdout");
    }

    if cli.dry_run {
        info!("Running in dry-run mode, no changes will be made");
    }

    let context = AppContext {
        config,
        template: cli.template,
        timeout: cli.timeout,
        threads: cli.threads,
        dry_run: cli.dry_run,
        print_stdout,
    };

    match &cli.action {
        Action::Config => {
            println!("{}", context.config);
        }
        Action::Start { .. } => {
            start(&context)?;
        }
        Action::Stop => {
            stop()?;
        }
        Action::Restart => {
            stop()?;
            start(&context)?;
        }
        Action::Refresh { .. } => {
            refresh(&context)?;
        }
    }

    info!("Operation completed successfully");
    Ok(())
}
