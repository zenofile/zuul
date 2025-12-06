// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

#![feature(addr_parse_ascii, likely_unlikely, slice_split_once)]

mod cidr;
mod cli;
mod config;
mod istr;
mod threadpool;

#[cfg(feature = "sandbox")]
mod sandbox;

use anyhow::{Context, Result};
use clap::Parser;
use core::hint::likely;
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::{IsTerminal, Write},
    path::PathBuf,
    process::{Command, Output},
    sync::Arc,
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;

use crate::{
    cidr::{Ipv4Prefix, Ipv6Prefix, SafeIpv4Prefix, SafeIpv6Prefix},
    cli::{Action, Cli},
    config::{Config, IpVersion, resolve_fragment},
    istr::IStr,
    threadpool::ThreadPool,
};

#[derive(Debug)]
struct AppContext {
    config: Config,
    template: PathBuf,
    timeout: u64,
    threads: usize,
    verbosity: u8,
    dry_run: bool,
    print_stdout: bool,
}

type NetSets<T> = HashMap<IStr, BTreeSet<T>>;

#[inline]
#[must_use]
fn parse_v4_net_bytes(input: &[u8]) -> Option<ipnet::Ipv4Net> {
    let (ip_bytes, prefix) = match input.split_once(|&b| b == b'/') {
        Some((ip, p)) => (ip, SafeIpv4Prefix::try_from(p).ok()?.into()),
        // Default is /32 for IPv4
        None => (input, Ipv4Prefix::new(32)?),
    };

    let ip = std::net::Ipv4Addr::parse_ascii(ip_bytes).ok()?;
    ipnet::Ipv4Net::new(ip, prefix.as_u8()).ok()
}

#[inline]
#[must_use]
pub fn parse_v6_net_bytes(input: &[u8]) -> Option<ipnet::Ipv6Net> {
    let (ip_bytes, prefix) = match input.split_once(|&b| b == b'/') {
        Some((ip, p)) => (ip, SafeIpv6Prefix::try_from(p).ok()?.into()),
        // Default is /128 for IPv6
        None => (input, Ipv6Prefix::new(128)?),
    };

    let ip = std::net::Ipv6Addr::parse_ascii(ip_bytes).ok()?;
    ipnet::Ipv6Net::new(ip, prefix.as_u8()).ok()
}

#[derive(Debug)]
struct IpSets {
    v4_sets: NetSets<ipnet::Ipv4Net>,
    v6_sets: NetSets<ipnet::Ipv6Net>,
}

impl IpSets {
    #[must_use]
    fn new() -> Self {
        Self {
            v4_sets: HashMap::new(),
            v6_sets: HashMap::new(),
        }
    }

    #[inline]
    #[must_use]
    fn strip_comment_and_trim_bytes(line: &[u8]) -> &[u8] {
        let text = line
            .iter()
            .position(|&b| b == b'#')
            .map_or(line, |pos| &line[..pos]);

        text.trim_ascii()
    }

    #[inline]
    fn log_results(set_name: &str, url: &str, added: usize, invalid: usize) {
        if invalid > 0 {
            warn!(
                "Skipped {} invalid entries in {} for {}",
                invalid, set_name, url
            );
        }
        debug!("Set {}: Added {} new entries from {}", set_name, added, url);
    }

    fn process_ips<T, F>(
        target_map: &mut NetSets<T>,
        set_name: &str,
        data: (&str, &[u8]),
        parser: F,
    ) where
        T: Ord + Copy + std::fmt::Debug,
        F: Fn(&[u8]) -> Option<T>,
    {
        let (url, content) = data;
        let target_set = target_map.entry(IStr::from(set_name)).or_default();

        // Iterate over lines using byte splitting (zero allocation)
        let (added, invalid) = content
            .split(|&b| b == b'\n')
            .map(Self::strip_comment_and_trim_bytes)
            .filter(|s| !s.is_empty())
            .fold((0, 0), |(mut added, mut invalid), line_bytes| {
                if let Some(net) = parser(line_bytes) {
                    if target_set.insert(net) {
                        added += 1;
                    }
                } else {
                    invalid += 1;
                    // We construct a String only for the debug log of an invalid entry
                    if tracing::level_enabled!(tracing::Level::DEBUG) {
                        debug!("Invalid IP entry: {}", String::from_utf8_lossy(line_bytes));
                    }
                }
                (added, invalid)
            });

        Self::log_results(set_name, url, added, invalid);
    }

    fn process_content(&mut self, version: IpVersion, set_name: &str, data: (&str, &[u8])) {
        match version {
            IpVersion::V4 => {
                Self::process_ips(&mut self.v4_sets, set_name, data, parse_v4_net_bytes);
            }
            IpVersion::V6 => {
                Self::process_ips(&mut self.v6_sets, set_name, data, parse_v6_net_bytes);
            }
        }
    }

    // Optimized for fewer allocations
    fn get_formatted_generic<T>(map: &NetSets<T>, set_name: &str) -> Option<String>
    where
        T: std::fmt::Display,
    {
        use std::fmt::Write as _;
        map.get(set_name).map(|nets| {
            if nets.is_empty() {
                return String::new();
            }
            // Heuristic pre-allocation: ~20 bytes per entry (IP + formatting)
            let mut buf = String::with_capacity(nets.len() * 20);
            for (i, net) in nets.iter().enumerate() {
                if likely(i > 0) {
                    buf.push_str(",\n\t\t");
                }
                // Write directly to buffer using std::fmt::Write
                let _ = write!(buf, "{}", net);
            }
            buf
        })
    }

    fn get_formatted(&self, version: IpVersion, set_name: &str) -> Option<String> {
        match version {
            IpVersion::V4 => Self::get_formatted_generic(&self.v4_sets, set_name),
            IpVersion::V6 => Self::get_formatted_generic(&self.v6_sets, set_name),
        }
    }
}

#[derive(Debug, Clone)]
struct DownloadJob {
    url: IStr,
}

#[derive(Debug)]
struct DownloadResult {
    url: IStr,
    content: Result<Vec<u8>>,
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
    let content = (|| -> Result<Vec<u8>> {
        let mut dst = Vec::new();
        let mut easy = curl::easy::Easy::new();

        easy.url(&job.url)
            .context(format!("Failed to set URL: {}", job.url))?;
        easy.timeout(std::time::Duration::from_secs(timeout))
            .context("Failed to set timeout")?;
        easy.useragent("Mozilla/5.0 (compatible; zuul/0.1.0)")
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

        debug!("Got {} bytes of data from {}", dst.len(), job.url);

        Ok(dst)
    })();

    DownloadResult {
        url: job.url,
        content,
    }
}

// Returns a Receiver that yields results as they finish
fn start_downloads(
    pool: Arc<ThreadPool<DownloadJob, DownloadResult>>,
    urls: Vec<IStr>,
) -> kanal::Receiver<DownloadResult> {
    let (tx, rx) = kanal::bounded(pool.workers.len() * 2);

    // Job producer
    std::thread::spawn(move || {
        for url in urls {
            // This blocks if workers are full, acting as natural backpressure
            if pool.execute(DownloadJob { url }, tx.clone()).is_err() {
                break;
            }
        }
        // tx is dropped here, closing the channel when done
    });

    rx
}

fn generate_abuselist_urls<S: AsRef<str>>(entries: &[String], tmpl_urls: &[S]) -> Vec<IStr> {
    let mut urls = Vec::with_capacity(entries.len() * tmpl_urls.len().max(1));

    for entry in entries {
        let trimmed = entry.trim();

        // Direct URLs
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(IStr::from(trimmed));
            continue;
        }

        // ASN processing
        if trimmed.len() >= 2 && trimmed[..2].eq_ignore_ascii_case("as") {
            let digits = &trimmed[2..];
            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                warn!(
                    "Invalid ASN format (must be AS followed by digits): {}",
                    trimmed
                );
                continue;
            }

            if tmpl_urls.is_empty() {
                warn!(
                    "Skipping ASN entry {} because no source URLs are configured for this IP version",
                    trimmed
                );
                continue;
            }

            info!("Processing ASN entry: AS{}", digits);
            urls.extend(
                tmpl_urls
                    .iter()
                    .map(|tmpl| IStr::from(tmpl.as_ref().replace("{asn}", digits))),
            );
        } else {
            warn!(
                "Ignoring entry with unknown format in abuselist: {}",
                trimmed
            );
        }
    }

    urls
}

fn generate_country_urls<S: AsRef<str>>(countries: &[String], tmpl_urls: &[S]) -> Vec<IStr> {
    countries
        .iter()
        .map(|country| country.to_lowercase())
        .flat_map(|country_lower| {
            tmpl_urls
                .iter()
                .map(move |tmpl| IStr::from(tmpl.as_ref().replace("{country}", &country_lower)))
        })
        .collect()
}

fn generate_nftable(context: &AppContext, sets: &IpSets) -> Result<String> {
    let template_content =
        fs::read_to_string(&context.template).context("Failed to read template file")?;

    let mut jinja = minijinja::Environment::new();
    jinja.set_trim_blocks(true);
    jinja.set_lstrip_blocks(true);
    jinja.add_template("zuul", &template_content)?;
    let template = jinja.get_template("zuul")?;

    let mut set_data = HashMap::with_capacity(8);
    let cfg = &context.config;

    // Configured set names
    let base_set_names = [
        &cfg.set_names.whitelist,
        &cfg.set_names.blacklist,
        &cfg.set_names.abuselist,
        &cfg.set_names.country,
    ];

    // ... with ip version appended
    set_data.extend(cfg.ip_versions.get_active().flat_map(|ip_version| {
        base_set_names.iter().map(move |base_name| {
            let full_name = format!("{}_{}", base_name, ip_version);
            let nets = sets
                .get_formatted(ip_version, &full_name)
                .unwrap_or_default();
            (full_name, nets)
        })
    }));

    // Render template with all context
    use minijinja::context;

    let rules = template.render(context! {
        iifname => &cfg.iifname,
        default_policy => &cfg.default_policy,
        block_policy => &cfg.block_policy,
        logging => &cfg.logging,
        set_names => &cfg.set_names,
        sets => set_data,
        ip_versions => context! {
            v4 => cfg.ip_versions.v4,
            v6 => cfg.ip_versions.v6,
        },
    })?;

    Ok(rules)
}

fn collect_ip_sets(context: &AppContext) -> IpSets {
    let cfg = &context.config;
    let mut sets = IpSets::new();
    let pool = Arc::new(ThreadPool::downloader(context.threads, context.timeout));

    // We map every URL to the target set name so we know where to put the data later
    let mut url_map: HashMap<IStr, (IStr, IpVersion)> = HashMap::new();
    let mut all_urls = Vec::new();

    for ip_version in cfg.ip_versions.get_active() {
        // Direct ip entry processing
        // Whitelist
        if let Some(entries) = cfg.whitelist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = format!("{}_{}", cfg.set_names.whitelist, ip_version);
            let nets = entries.join("\n");
            let src = "direct:WHITELIST";

            sets.process_content(ip_version, &set_name, (src, nets.as_bytes()));
        }

        // Blacklist
        if let Some(entries) = cfg.blacklist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = format!("{}_{}", cfg.set_names.blacklist, ip_version);
            let nets = entries.join("\n");
            let src = "direct:BLACKLIST";

            sets.process_content(ip_version, &set_name, (src, nets.as_bytes()));
        }

        // Handle remote content
        // Abuselist
        if let Some(entries) = cfg.abuselist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = IStr::from(format!("{}_{}", cfg.set_names.abuselist, ip_version));
            let asn_tmpl = cfg.sources.asn.get(ip_version);

            if asn_tmpl.is_empty() {
                debug!("Skipping ASN list for {} (source disabled)", ip_version);
                continue;
            }

            all_urls.extend(
                generate_abuselist_urls(entries, asn_tmpl)
                    .into_iter()
                    .inspect(|url| {
                        url_map.insert(url.clone(), (set_name.clone(), ip_version));
                    }),
            );
        }

        // Country List
        if let Some(countries) = &cfg.country_list {
            let set_name = IStr::from(format!("{}_{}", cfg.set_names.country, ip_version));
            let country_tmpl = cfg.sources.country.get(ip_version);

            if country_tmpl.is_empty() {
                debug!("Skipping country list for {} (source disabled)", ip_version);
                continue;
            }

            all_urls.extend(
                generate_country_urls(countries, country_tmpl)
                    .into_iter()
                    .inspect(|url| {
                        url_map.insert(url.clone(), (set_name.clone(), ip_version));
                    }),
            );
        }
    }

    // Start (consume) all downloads. Returns immediately with a receiver
    let rx = start_downloads(pool, all_urls);

    // Iterate as they finish (this blocks only as needed)
    for result in rx {
        let text = match result.content {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to download {}: {}", result.url, e);
                continue;
            }
        };

        let Some((set_name, version)) = url_map.remove(&result.url) else {
            // Optionally log that a result arrived for an unknown/duplicate URL
            continue;
        };

        // Computational expensive, debug mode only
        if context.verbosity >= 2 {
            // Skip unicode validation for line counting
            #[allow(clippy::naive_bytecount)]
            let count = text.iter().filter(|&&b| b == b'\n').count() + 1;
            debug!("Processing {} lines for {}", count, set_name);
        }
        sets.process_content(version, &set_name, (&result.url, &text));
    }

    let (total_v4, total_v6) = calculate_totals(&sets);
    info!(
        "Total entries IPv4: {} IPv6: {} total: {}",
        total_v4,
        total_v6,
        total_v4 + total_v6
    );

    sets
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

fn calculate_totals(sets: &IpSets) -> (usize, usize) {
    let total_v4: usize = sets
        .v4_sets
        .iter()
        .inspect(|(name, set)| info!("Set {}: {} unique IPv4 networks", name, set.len()))
        .map(|(_, set)| set.len())
        .sum();

    let total_v6: usize = sets
        .v6_sets
        .iter()
        .inspect(|(name, set)| info!("Set {}: {} unique IPv6 networks", name, set.len()))
        .map(|(_, set)| set.len())
        .sum();
    (total_v4, total_v6)
}

fn start(context: &AppContext) -> Result<()> {
    info!("Starting zuul");
    let sets = collect_ip_sets(context);
    let rules = generate_nftable(context, &sets)?;

    if context.print_stdout {
        write_to_stdout(&rules)?;
    }
    run_nft_stdin(&rules, context.dry_run)?;

    Ok(())
}

fn stop() -> Result<()> {
    info!("Stopping zuul");
    run_nft_cli(&["delete", "table", "netdev", "blackhole"], false)?;
    info!("Successfully deleted nftables table 'netdev blackhole'");

    Ok(())
}

fn refresh(context: &AppContext) -> Result<()> {
    use std::fmt::Write as _;

    info!("Reloading abuselist and country lists");

    let mut commands = String::with_capacity(8192);
    let cfg = &context.config;

    for ip_version in cfg.ip_versions.get_active() {
        let abuselist_set = format!("{}_{}", cfg.set_names.abuselist, ip_version);
        let country_set = format!("{}_{}", cfg.set_names.country, ip_version);

        writeln!(commands, "flush set netdev blackhole {}", abuselist_set)?;
        writeln!(commands, "flush set netdev blackhole {}", country_set)?;
    }
    let sets = collect_ip_sets(context);

    for ip_version in cfg.ip_versions.get_active() {
        let abuselist_set = format!("{}_{}", cfg.set_names.abuselist, ip_version);
        let country_set = format!("{}_{}", cfg.set_names.country, ip_version);

        let abuselist_elements = sets.get_formatted(ip_version, &abuselist_set);

        if let Some(elements) = abuselist_elements
            && !elements.is_empty()
        {
            writeln!(
                commands,
                "add element netdev blackhole {} {{ {} }}",
                abuselist_set, elements
            )?;
        }

        let country_elements = sets.get_formatted(ip_version, &country_set);

        if let Some(elements) = country_elements
            && !elements.is_empty()
        {
            writeln!(
                commands,
                "add element netdev blackhole {} {{ {} }}",
                country_set, elements
            )?;
        }
    }

    if !commands.is_empty() {
        if context.print_stdout {
            write_to_stdout(&commands)?;
        }
        run_nft_stdin(&commands, context.dry_run)?;
    }

    let (total_v4, total_v6) = calculate_totals(&sets);
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

        // journald
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into()))
            .with(journald_layer)
            .init();
    } else {
        // tty
        let use_ansi = std::io::stdout().is_terminal();
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into()),
            )
            .with_writer(std::io::stderr)
            .with_ansi(use_ansi)
            .init();
    }

    let config_path = resolve_fragment(cli.config, "config.yaml")?;
    let template_path = resolve_fragment(cli.template, "template.jinja2")?;

    // Landlock init
    #[cfg(feature = "sandbox")]
    match sandbox::harden([&config_path, &template_path]) {
        Ok(sandbox::Status::Full) => info!("Landlock sandbox fully active."),
        Ok(status) if cli.enforce_sandbox => {
            anyhow::bail!("Fatal: Sandbox is enforced but status is: {}", status)
        }
        Ok(status) => warn!("Landlock sandbox is only {}.", status),
        Err(e) if cli.enforce_sandbox => {
            return Err(e).context("Fatal: Failed to initialize sandbox");
        }
        Err(e) => warn!("Failed to initialize sandbox: {:#}", e),
    }

    let config = Config::load(&config_path)?;

    for iface in &config.iifname {
        info!("Using network interface: {}", iface);
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
        template: template_path,
        timeout: cli.timeout,
        threads: cli.threads,
        verbosity: cli.verbose,
        dry_run: cli.dry_run,
        print_stdout,
    };

    match &cli.action {
        Action::Config => {
            println!("{:#?}", context.config);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cidr::Ipv6Prefix;

    // Tests for parse_v4_net_bytes
    #[test]
    fn test_parse_v4_net_bytes_with_prefix() {
        let result = parse_v4_net_bytes(b"192.168.1.0/24");
        assert!(result.is_some());
        let net = result.unwrap();
        assert_eq!(net.addr(), std::net::Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_parse_v4_net_bytes_without_prefix() {
        let result = parse_v4_net_bytes(b"192.168.1.1");
        assert!(result.is_some());
        // Should default to /32
    }

    #[test]
    fn test_parse_v4_net_bytes_invalid() {
        assert!(parse_v4_net_bytes(b"invalid").is_none());
        assert!(parse_v4_net_bytes(b"192.168.1.0/33").is_none()); // Invalid prefix
        assert!(parse_v4_net_bytes(b"").is_none());
    }

    // Tests for parse_v6_net_bytes
    #[test]
    fn test_parse_v6_net_bytes_with_prefix() {
        let result = parse_v6_net_bytes(b"2001:db8::/32");
        assert!(result.is_some());
        let net = result.unwrap();
        assert_eq!(net.addr().to_string(), "2001:db8::");
    }

    #[test]
    fn test_parse_v6_net_bytes_without_prefix() {
        let result = parse_v6_net_bytes(b"::1");
        assert!(result.is_some());
        // Should default to /128
    }

    #[test]
    fn test_parse_v6_net_bytes_invalid() {
        assert!(parse_v6_net_bytes(b"invalid").is_none());
        assert!(parse_v6_net_bytes(b"2001:db8::/129").is_none()); // Invalid prefix
        assert!(parse_v6_net_bytes(b"").is_none());
    }

    // Property-based style tests
    #[test]
    fn test_ipv6_prefix_roundtrip() {
        for i in 0..=128 {
            let prefix = Ipv6Prefix::new(i).unwrap();
            assert_eq!(prefix.as_u8(), i);
            let value: u8 = prefix.into();
            assert_eq!(value, i);
        }
    }

    // Helper to build a NetSets<String> for formatting tests.
    fn make_string_set_map() -> NetSets<String> {
        NetSets::default()
    }

    // Helper parser for process_ips tests: parses ASCII lines into u32,
    // returns None on invalid input.
    fn parse_u32_bytes(line: &[u8]) -> Option<u32> {
        std::str::from_utf8(line).ok()?.parse::<u32>().ok()
    }

    // Tests for IpSets::new
    #[test]
    fn new_starts_with_empty_maps() {
        let sets = IpSets::new();

        assert!(sets.v4_sets.is_empty());
        assert!(sets.v6_sets.is_empty());
    }

    // Tests for strip_comment_and_trim_bytes
    #[test]
    fn strip_comment_trims_whitespace_only() {
        let line = b"   \t  example.com  \t ";
        let out = IpSets::strip_comment_and_trim_bytes(line);
        assert_eq!(out, b"example.com");
    }

    #[test]
    fn strip_comment_removes_trailing_comment() {
        let line = b"10.0.0.0/8   # private v4 range";
        let out = IpSets::strip_comment_and_trim_bytes(line);
        assert_eq!(out, b"10.0.0.0/8");
    }

    #[test]
    fn strip_comment_handles_only_comment_line() {
        let line = b"# just a comment";
        let out = IpSets::strip_comment_and_trim_bytes(line);
        assert!(out.is_empty());
    }

    #[test]
    fn strip_comment_handles_empty_and_whitespace_lines() {
        let line1 = b"";
        let line2 = b"   \t   ";
        assert!(IpSets::strip_comment_and_trim_bytes(line1).is_empty());
        assert!(IpSets::strip_comment_and_trim_bytes(line2).is_empty());
    }

    #[test]
    fn strip_comment_handles_crlf_newlines() {
        let line = b"192.168.0.0/16\r\n# comment";
        // Function sees only the line bytes; simulate a single logical line.
        let out = IpSets::strip_comment_and_trim_bytes(line);
        assert_eq!(out, b"192.168.0.0/16");
    }

    // Tests for process_ips
    #[test]
    fn process_ips_inserts_valid_and_skips_invalid() {
        // Use a simple numeric type (u32) for T with a custom parser.
        let mut map = NetSets::<u32>::default();

        // Lines:
        //  "1"     -> valid
        //  "2"     -> valid
        //  "bad"   -> invalid
        //  "2"     -> duplicate (should not increase set size)
        let content = b"1\n2\nbad\n2\n";
        let url = "memory://test";

        IpSets::process_ips(&mut map, "test-set", (url, content), parse_u32_bytes);

        let set = map.get("test-set").expect("set should exist");
        // Valid unique entries: {1, 2}
        assert_eq!(set.len(), 2);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
    }

    #[test]
    fn process_ips_creates_set_if_missing() {
        let mut map = NetSets::<u32>::default();
        let content = b"42\n";
        let url = "memory://test";

        assert!(!map.contains_key("new-set"));

        IpSets::process_ips(&mut map, "new-set", (url, content), parse_u32_bytes);

        let set = map.get("new-set").expect("set should have been created");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&42));
    }

    #[test]
    fn process_ips_ignores_blank_and_comment_lines() {
        let mut map = NetSets::<u32>::default();
        let content = b"\n# full comment\n  \t # comment with leading ws\n7\n";
        let url = "memory://test";

        IpSets::process_ips(&mut map, "comments", (url, content), parse_u32_bytes);

        let set = map.get("comments").expect("set should exist");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&7));
    }

    // Test for get_formatted_*
    #[test]
    fn get_formatted_generic_returns_none_for_unknown_set() {
        let map: NetSets<String> = make_string_set_map();
        let out = IpSets::get_formatted_generic(&map, "missing");
        assert!(out.is_none());
    }

    #[test]
    fn get_formatted_generic_returns_empty_string_for_empty_set() {
        let mut map: NetSets<String> = make_string_set_map();
        // Create an empty set entry under "empty"
        let _ = map.entry(IStr::from("empty")).or_default();

        let out = IpSets::get_formatted_generic(&map, "empty").expect("entry should exist");
        assert!(out.is_empty());
    }

    #[test]
    fn get_formatted_generic_formats_single_entry_without_separator() {
        let mut map: NetSets<String> = make_string_set_map();
        let set = map.entry(IStr::from("single")).or_default();
        set.insert("10.0.0.0/8".to_string());

        let out = IpSets::get_formatted_generic(&map, "single").expect("entry should exist");
        assert_eq!(out, "10.0.0.0/8");
    }

    #[test]
    fn get_formatted_generic_formats_multiple_entries_with_separator() {
        let mut map: NetSets<String> = make_string_set_map();
        let set = map.entry(IStr::from("multi")).or_default();

        // BTreeSet iteration order is sorted, so we can assert exact output.
        set.insert("10.0.0.0/8".to_string());
        set.insert("192.168.0.0/16".to_string());

        let out = IpSets::get_formatted_generic(&map, "multi").expect("entry should exist");

        let expected = "10.0.0.0/8,\n\t\t192.168.0.0/16";
        assert_eq!(out, expected);
    }

    #[test]
    fn get_formatted_dispatches_on_version() {
        let mut sets = IpSets::new();

        // Feed content through the real pipeline so the correct net types are used.
        let v4_data = ("memory://v4", b"10.0.0.0/8\n" as &[u8]);
        let v6_data = ("memory://v6", b"fd00::/8\n" as &[u8]);

        sets.process_content(IpVersion::V4, "test", v4_data);
        sets.process_content(IpVersion::V6, "test", v6_data);

        let v4_str = sets
            .get_formatted(IpVersion::V4, "test")
            .expect("v4 set should exist");
        let v6_str = sets
            .get_formatted(IpVersion::V6, "test")
            .expect("v6 set should exist");

        assert_eq!(v4_str, "10.0.0.0/8");
        assert_eq!(v6_str, "fd00::/8");
    }
}
