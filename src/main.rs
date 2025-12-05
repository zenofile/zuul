// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

mod cli;
mod config;
mod istr;
mod threadpool;

#[cfg(feature = "sandbox")]
mod sandbox;

use anyhow::{Context, Result};
use clap::Parser;
use ipnet::{Ipv4Net, Ipv6Net};
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

/// Generic `NetSet` type
type NetSets<T> = HashMap<IStr, BTreeSet<T>>;

#[derive(Debug)]
struct IpSets {
    v4_sets: NetSets<Ipv4Net>,
    v6_sets: NetSets<Ipv6Net>,
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
        line.split_once('#')
            .map_or(line, |(before, _)| before)
            .trim()
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

    fn process_ips<T, F>(target_map: &mut NetSets<T>, set_name: &str, data: (&str, &str), parser: F)
    where
        T: Ord + Copy + std::fmt::Debug,
        F: Fn(&str) -> Option<T>,
    {
        let (url, content) = data;
        let target_set = target_map.entry(IStr::from(set_name)).or_default();

        let (added, invalid) = content
            .lines()
            .map(Self::strip_comment_and_trim)
            .filter(|s| !s.is_empty())
            .fold((0, 0), |(mut added, mut invalid), line| {
                if let Some(net) = parser(line) {
                    if target_set.insert(net) {
                        added += 1;
                    }
                } else {
                    invalid += 1;
                    debug!("Invalid IP entry: {}", line);
                }
                (added, invalid)
            });

        Self::log_results(set_name, url, added, invalid);
    }

    fn process_content(&mut self, version: IpVersion, set_name: &str, data: (&str, &str)) {
        match version {
            IpVersion::V4 => Self::process_ips(&mut self.v4_sets, set_name, data, |s| {
                s.parse::<Ipv4Net>().ok().or_else(|| {
                    s.parse::<std::net::Ipv4Addr>()
                        .ok()
                        .map(|a| Ipv4Net::new(a, 32).unwrap())
                })
            }),
            IpVersion::V6 => Self::process_ips(&mut self.v6_sets, set_name, data, |s| {
                s.parse::<Ipv6Net>().ok().or_else(|| {
                    s.parse::<std::net::Ipv6Addr>()
                        .ok()
                        .map(|a| Ipv6Net::new(a, 128).unwrap())
                })
            }),
        }
    }

    fn get_formatted_generic<T>(map: &NetSets<T>, set_name: &str) -> Option<String>
    where
        T: std::fmt::Display,
    {
        map.get(set_name).map(|nets| {
            nets.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<String>>()
                .join(",\n\t\t")
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

        let text = String::from_utf8(dst).context("Failed to parse response body as UTF-8")?;
        debug!("Got {} bytes of data from {}", text.len(), job.url);

        Ok(text)
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

            sets.process_content(ip_version, &set_name, (src, &nets));
        }

        // Blacklist
        if let Some(entries) = cfg.blacklist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = format!("{}_{}", cfg.set_names.blacklist, ip_version);
            let nets = entries.join("\n");
            let src = "direct:BLACKLIST";

            sets.process_content(ip_version, &set_name, (src, &nets));
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
            let count = text.as_bytes().iter().filter(|&&b| b == b'\n').count() + 1;
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

    let mut flush_commands = String::with_capacity(512);

    let cfg = &context.config;
    for ip_version in cfg.ip_versions.get_active() {
        let abuselist_set = format!("{}_{}", cfg.set_names.abuselist, ip_version);
        let country_set = format!("{}_{}", cfg.set_names.country, ip_version);

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

    for ip_version in cfg.ip_versions.get_active() {
        let abuselist_set = format!("{}_{}", cfg.set_names.abuselist, ip_version);
        let country_set = format!("{}_{}", cfg.set_names.country, ip_version);

        let abuselist_elements = sets.get_formatted(ip_version, &abuselist_set);

        if let Some(elements) = abuselist_elements
            && !elements.is_empty()
        {
            writeln!(
                add_commands,
                "add element netdev blackhole {} {{ {} }}",
                abuselist_set, elements
            )?;
        }

        let country_elements = sets.get_formatted(ip_version, &country_set);

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
