#![feature(
    addr_parse_ascii,
    cold_path,
    likely_unlikely,
    slice_split_once,
    slice_partition_dedup
)]

mod cidr;
mod cli;
mod config;
mod istr;
mod threadpool;

#[cfg(feature = "sandbox")]
mod sandbox;

use core::hint::likely;
use std::{
    collections::HashMap,
    fs,
    hint::{cold_path, unlikely},
    io::{BufRead, BufReader, Cursor, IsTerminal, Write},
    path::PathBuf,
    process::{Command, Output},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use ipnet::{Ipv4Net, Ipv6Net};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::prelude::*;

use crate::{
    cidr::{ParsedResult, parse_v4_net_bytes, parse_v6_net_bytes},
    cli::{Action, Cli},
    config::{Config, IpVersion, ListEntry, resolve_fragment},
    istr::IStr,
    threadpool::ThreadPool,
};

// BTreeMap is just too slow, sorry
type NetSet<T> = Vec<T>;
type NetSets<T> = HashMap<IStr, Arc<NetSet<T>>>;

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

#[derive(Debug, Clone)]
struct DownloadJob {
    url: IStr,
}

#[derive(Debug)]
enum InputSource {
    Temp(tempfile::NamedTempFile),
    Local(PathBuf),
}

#[derive(Debug)]
struct DownloadResult {
    url: IStr,
    source: Result<InputSource>,
}

struct ProcessingInput<'a, R> {
    pub source: &'a str,
    pub reader: R,
    pub min_prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SetType {
    Static,
    Dynamic,
}

#[derive(Debug, Clone)]
struct LazyIpSet<T> {
    data: Arc<NetSet<T>>,
    set_type: SetType,
}

impl<T> std::fmt::Display for LazyIpSet<T>
where
    T: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, net) in self.data.iter().enumerate() {
            if i > 0 {
                f.write_str(",\n\t\t")?;
            }
            write!(f, "{}", net)?;
        }
        Ok(())
    }
}

mod minijinja_impl {
    use std::{fmt, sync::Arc};

    use minijinja::value::Value;

    use crate::{LazyIpSet, SetType};

    impl<T> minijinja::value::Object for LazyIpSet<T>
    where
        T: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        // Override is_true so {% if sets.name %} works naturally.
        // By default, Objects are always "true" unless they implement enumerator_len,
        // which we don't. We want empty sets to be skipped in the template.
        fn is_true(self: &Arc<Self>) -> bool {
            !self.data.is_empty()
        }

        // Override render to force usage of our Display impl.
        // Without this, Minijinja might treat this as an opaque struct/map
        // and print a debug representation (like `{}`) instead of our formatted list.
        fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self, f)
        }

        // This allows {{ set.is_static }} or {{ set.type }}
        fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
            match key.as_str()? {
                "is_static" => Some(Value::from(self.set_type == SetType::Static)),
                "type" => Some(Value::from(match self.set_type {
                    SetType::Static => "static",
                    SetType::Dynamic => "dynamic",
                })),
                "len" => Some(Value::from(self.data.len())),
                _ => None,
            }
        }
    }
}

#[inline]
#[must_use]
fn get_epoch_suffix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
struct SetProcessor<'a> {
    cfg: &'a Config,
    sets: &'a IpSets,
    suffix: u64,
}

impl<'a> SetProcessor<'a> {
    const fn new(cfg: &'a Config, sets: &'a IpSets, suffix: u64) -> Self {
        Self { cfg, sets, suffix }
    }

    /// Iterates over all active sets of the given type.
    /// The callback receives: (IP Version, Set Name, `LazyIpSet` Object)
    fn for_each_set<F>(&self, set_type: SetType, mut callback: F) -> Result<()>
    where
        F: FnMut(IpVersion, &str, &minijinja::Value) -> Result<()>,
    {
        let cfg = self.cfg;
        let targets = match set_type {
            SetType::Static => [&cfg.set_names.whitelist, &cfg.set_names.blacklist],
            SetType::Dynamic => [&cfg.set_names.abuselist, &cfg.set_names.country],
        };

        let suffix_str = if set_type == SetType::Dynamic {
            format!("_{}", self.suffix)
        } else {
            String::new()
        };

        for ip_version in cfg.net.get_active() {
            for base_name in &targets {
                let full_name = format!("{}_{}{}", base_name, ip_version, suffix_str);

                // Retrieve the set as a Minijinja Value (wrapping LazyIpSet)
                let val = match ip_version {
                    IpVersion::V4 => self.sets.v4_sets.get(full_name.as_str()).map(|s| {
                        minijinja::Value::from_object(LazyIpSet {
                            data: s.clone(),
                            set_type,
                        })
                    }),
                    IpVersion::V6 => self.sets.v6_sets.get(full_name.as_str()).map(|s| {
                        minijinja::Value::from_object(LazyIpSet {
                            data: s.clone(),
                            set_type,
                        })
                    }),
                };

                if let Some(value) = val {
                    // Only yield if not empty (check using the Object trait we implemented)
                    if value.is_true() {
                        callback(ip_version, &full_name, &value)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct IpSets {
    v4_sets: NetSets<Ipv4Net>,
    v6_sets: NetSets<Ipv6Net>,
}

impl IpSets {
    #[must_use]
    fn new() -> Self {
        Self {
            v4_sets: HashMap::new(),
            v6_sets: HashMap::new(),
        }
    }

    #[must_use]
    fn strip_comment_and_trim_bytes(line: &[u8]) -> &[u8] {
        let text = line
            .iter()
            .position(|&b| b == b'#')
            .map_or(line, |pos| &line[..pos]);

        text.trim_ascii()
    }

    fn discard_line<R: BufRead>(reader: &mut R, source: Option<&str>) {
        loop {
            let buf = match reader.fill_buf() {
                Ok(b) => b,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if let Some(file) = source {
                        error!("Error discarding line in {}: {}", file, e);
                    } else {
                        error!("Error discarding line {}", e);
                    }
                    break;
                }
            };

            if buf.is_empty() {
                break; // EOF reached
            }

            let len = buf.len();
            // Check if the newline exists in the current chunk
            if let Some(idx) = buf.iter().position(|&b| b == b'\n') {
                reader.consume(idx + 1);
                break;
            }
            reader.consume(len);
        }
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

    fn merge_into_map<R, T, F>(
        target_map: &mut NetSets<T>,
        set_name: &str,
        mut input: ProcessingInput<R>,
        parser: F,
    ) where
        R: BufRead,
        T: Ord + Copy + std::fmt::Debug + cidr::PrefixCheck,
        F: Fn(&[u8]) -> ParsedResult<T>,
    {
        let trusted_set = input.source.starts_with("inline:");
        let mut added = 0;
        let mut invalid = 0;

        const PAGE_ALIGNED_SIZE: usize = 4096;
        // We keep a buffer for the current line
        let mut line_buf = Vec::with_capacity(PAGE_ALIGNED_SIZE >> 2);
        let mut batch_buf = Vec::with_capacity(PAGE_ALIGNED_SIZE);

        loop {
            // Clear at the beginning because of early returns
            line_buf.clear();
            let mut limit_reader = std::io::Read::take(&mut input.reader, PAGE_ALIGNED_SIZE as u64);

            let bytes_read = match limit_reader.read_until(b'\n', &mut line_buf) {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(e) => {
                    cold_path();
                    warn!("Error reading from {}: {}", input.source, e);
                    break;
                }
            };

            if unlikely(
                bytes_read as u64 == PAGE_ALIGNED_SIZE as u64 && line_buf.last() != Some(&b'\n'),
            ) {
                warn!("Line too long in {}, discarding", input.source);
                // Pass the original reader to discard garbage
                Self::discard_line(&mut input.reader, Some(input.source));
                continue;
            }

            let line_bytes = Self::strip_comment_and_trim_bytes(&line_buf);
            if line_bytes.is_empty() {
                continue;
            }

            if let Some(net) = parser(line_bytes) {
                if likely(trusted_set || net.meets_min_prefix(input.min_prefix)) {
                    batch_buf.push(net);
                } else {
                    warn!(
                        "Skipping non-trusted IP range: {}",
                        String::from_utf8_lossy(line_bytes)
                    );
                    invalid += 1;
                }
            } else {
                cold_path();
                invalid += 1;
                if tracing::level_enabled!(tracing::Level::DEBUG) {
                    debug!("Invalid IP entry: {}", String::from_utf8_lossy(line_bytes));
                }
            }
        }

        let set = Arc::make_mut(target_map.entry(IStr::from(set_name)).or_default());
        let old_len = set.len();

        set.extend(batch_buf);
        set.sort_unstable();

        // partition_dedup moves duplicates to the end but doesn't truncate immediately
        let (unique, _duplicates) = set.partition_dedup();
        let new_len = unique.len();

        added += new_len - old_len;
        set.truncate(new_len);

        Self::log_results(set_name, input.source, added, invalid);
    }

    #[inline]
    fn process_input<R: BufRead>(
        &mut self,
        version: IpVersion,
        set_name: &str,
        input: ProcessingInput<R>,
    ) {
        match version {
            IpVersion::V4 => {
                Self::merge_into_map(&mut self.v4_sets, set_name, input, parse_v4_net_bytes);
            }
            IpVersion::V6 => {
                Self::merge_into_map(&mut self.v6_sets, set_name, input, parse_v6_net_bytes);
            }
        }
    }
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
    use std::{cell::RefCell, io::Seek, time::Duration};

    // Create a temporary file
    let temp_file = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            return DownloadResult {
                url: job.url,
                source: Err(anyhow::Error::from(e)),
            };
        }
    };

    trace!(
        "Writing to file {} for {}",
        temp_file.path().display(),
        job.url
    );

    // We wrap the file in a RefCell to use it within the curl callbacks
    let dst_cell = RefCell::new(temp_file);

    let result = (|| -> Result<()> {
        let mut easy = curl::easy::Easy::new();
        static USER_AGENT: &str = concat!(
            "Mozilla/5.0 (compatible; zuul/",
            env!("CARGO_PKG_VERSION"),
            ")"
        );

        easy.url(&job.url)
            .context(format!("Failed to set URL: {}", job.url))?;
        easy.timeout(Duration::from_secs(timeout))
            .context("Failed to set timeout")?;
        easy.useragent(USER_AGENT)
            .context("Failed to set user agent")?;
        easy.follow_location(true)
            .context("Failed to enable follow location")?;

        {
            let mut transfer = easy.transfer();
            // Write function now writes to the file
            transfer
                .write_function(|data| {
                    let mut file = dst_cell.borrow_mut();
                    file.write_all(data)
                        .map(|()| data.len())
                        .map_err(|_| curl::easy::WriteError::Pause)
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

        Ok(())
    })();

    DownloadResult {
        url: job.url,
        // We use and_then because seeking might fail
        source: result.and_then(|()| {
            let mut file = dst_cell.into_inner();
            file.rewind()
                .context("Failed to seek to start of downloaded file")?;

            Ok(InputSource::Temp(file))
        }),
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

fn process_local_files<I, S>(urls: I) -> impl Iterator<Item = DownloadResult>
where
    I: IntoIterator<Item = S>,
    S: Into<IStr>,
{
    urls.into_iter().map(|url| {
        let url = Into::<IStr>::into(url);
        let source = url.strip_prefix("file://").map_or_else(
            || Err(anyhow::anyhow!("Not a file:// URL")),
            |path| Ok(InputSource::Local(PathBuf::from(path))),
        );
        DownloadResult { url, source }
    })
}

fn generate_country_urls<S: AsRef<str>>(
    countries: &[String],
    tmpl_urls: &[S],
) -> impl Iterator<Item = IStr> {
    countries
        .iter()
        .map(|country| country.to_lowercase())
        .flat_map(|country_lower| {
            tmpl_urls
                .iter()
                .map(move |tmpl| IStr::from(tmpl.as_ref().replace("{country}", &country_lower)))
        })
}

#[derive(Debug, Clone)]
pub enum UrlEntry {
    Http { url: IStr, min_prefix: Option<u8> },
    File { path: IStr, min_prefix: Option<u8> },
}

fn generate_abuselist_urls<S: AsRef<str>>(entries: &[ListEntry], tmpl_urls: &[S]) -> Vec<UrlEntry> {
    let mut urls = Vec::with_capacity(entries.len() * tmpl_urls.len().max(1));

    for entry in entries {
        let (raw_str, custom_prefix) = entry.as_parts();
        let trimmed = raw_str.trim();

        // inline URLs
        if trimmed.starts_with("https://") {
            urls.push(UrlEntry::Http {
                url: IStr::from(trimmed),
                min_prefix: custom_prefix,
            });
            continue;
        }

        if trimmed.starts_with("file://") {
            urls.push(UrlEntry::File {
                path: IStr::from(trimmed),
                min_prefix: custom_prefix,
            });
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
                    "Skipping ASN entry {} because no source URLs are configured for this IP \
                     version",
                    trimmed
                );
                continue;
            }

            info!("Processing ASN entry: AS{}", digits);
            urls.extend(tmpl_urls.iter().map(|tmpl| UrlEntry::Http {
                url: IStr::from(tmpl.as_ref().replace("{asn}", digits)),
                min_prefix: custom_prefix,
            }));
        } else {
            warn!(
                "Ignoring entry with unknown format in abuselist: {}",
                trimmed
            );
        }
    }

    urls
}

fn render_template(
    context: &AppContext,
    sets: &IpSets,
    writer: &mut dyn Write,
    block_name: &str,
    suffix: u64,
) -> Result<()> {
    let template_content =
        fs::read_to_string(&context.template).context("Failed to read template file")?;

    let mut jinja = minijinja::Environment::new();
    jinja.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
    jinja.set_trim_blocks(true);
    jinja.set_lstrip_blocks(true);
    jinja.add_template("zuul", &template_content)?;
    let template = jinja.get_template("zuul")?;

    let processor = SetProcessor::new(&context.config, sets, suffix);
    let mut all_sets = HashMap::new();

    let mut collect = |_, name: &str, val: &minijinja::Value| {
        all_sets.insert(name.to_owned(), val.clone());
        Ok(())
    };

    processor.for_each_set(SetType::Static, &mut collect)?;
    processor.for_each_set(SetType::Dynamic, &mut collect)?;

    let cfg = &context.config;
    use minijinja::context;

    // Build map of logical_name -> actual_name for the template
    let mut set_mappings = HashMap::new();
    for ver in [IpVersion::V4, IpVersion::V6] {
        // Static sets don't change
        let wl = format!("{}_{}", cfg.set_names.whitelist, ver);
        set_mappings.insert(wl.clone(), wl);
        let bl = format!("{}_{}", cfg.set_names.blacklist, ver);
        set_mappings.insert(bl.clone(), bl);

        // Dynamic sets get suffix
        let al_log = format!("{}_{}", cfg.set_names.abuselist, ver);
        let al_act = format!("{}_{}_{}", cfg.set_names.abuselist, ver, suffix);
        set_mappings.insert(al_log, al_act);

        let cy_log = format!("{}_{}", cfg.set_names.country, ver);
        let cy_act = format!("{}_{}_{}", cfg.set_names.country, ver, suffix);
        set_mappings.insert(cy_log, cy_act);
    }

    let ctx = context! {
        iifname => &cfg.iifname,
        default_policy => &cfg.default_policy,
        block_policy => &cfg.block_policy,
        logging => &cfg.logging,
        set_names => &cfg.set_names,
        sets => all_sets,
        set_mappings => set_mappings,
        ip_versions => context! {
            v4 => cfg.net.v4.enabled,
            v6 => cfg.net.v6.enabled,
        },
    };

    template
        .eval_to_state(ctx)?
        .render_block_to_write(block_name, writer)?;

    Ok(())
}

fn collect_ip_sets(context: &AppContext, suffix: u64) -> IpSets {
    let cfg = &context.config;
    let mut sets = IpSets::new();
    let pool = Arc::new(ThreadPool::downloader(context.threads, context.timeout));

    // We map every URL to the target set name so we know where to put the data later
    let mut url_map: HashMap<IStr, (IStr, IpVersion, Option<u8>)> = HashMap::new();
    let mut http_urls = Vec::new();
    let mut file_urls = Vec::new();

    for ip_version in cfg.net.get_active() {
        let min_prefix = match ip_version {
            IpVersion::V4 => cfg.net.v4.min_prefix,
            IpVersion::V6 => cfg.net.v6.min_prefix,
        };

        // inline ip entry processing
        // Whitelist
        if let Some(entries) = cfg.whitelist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = format!("{}_{}", cfg.set_names.whitelist, ip_version);
            let nets = entries
                .iter()
                .map(|e| e.as_parts().0)
                .collect::<Vec<_>>()
                .join("\n");

            let input = ProcessingInput {
                source: "inline:WHITELIST",
                reader: Cursor::new(nets.into_bytes()),
                min_prefix,
            };

            sets.process_input(ip_version, &set_name, input);
        }

        // Blacklist
        if let Some(entries) = cfg.blacklist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = format!("{}_{}", cfg.set_names.blacklist, ip_version);
            let nets = entries
                .iter()
                .map(|e| e.as_parts().0)
                .collect::<Vec<_>>()
                .join("\n");
            let input = ProcessingInput {
                source: "inline:BLACKLIST",
                reader: Cursor::new(nets.into_bytes()),
                min_prefix,
            };

            sets.process_input(ip_version, &set_name, input);
        }

        // Prepare retrieval of remote content
        // Abuselist
        if let Some(entries) = cfg.abuselist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = IStr::from(format!(
                "{}_{}_{}",
                cfg.set_names.abuselist, ip_version, suffix
            ));
            let asn_tmpl = cfg.sources.asn.get(ip_version);

            if asn_tmpl.is_empty() {
                debug!("Skipping ASN list for {} (source disabled)", ip_version);
                continue;
            }

            for entry in generate_abuselist_urls(entries, asn_tmpl) {
                match entry {
                    UrlEntry::Http { url, min_prefix } => {
                        url_map.insert(url.clone(), (set_name.clone(), ip_version, min_prefix));
                        http_urls.push(url);
                    }
                    UrlEntry::File { path, min_prefix } => {
                        url_map.insert(path.clone(), (set_name.clone(), ip_version, min_prefix));
                        file_urls.push(path);
                    }
                }
            }
        }

        // Country List
        if let Some(countries) = &cfg.country_list {
            let set_name = IStr::from(format!(
                "{}_{}_{}",
                cfg.set_names.country, ip_version, suffix
            ));
            let country_tmpl = cfg.sources.country.get(ip_version);

            if country_tmpl.is_empty() {
                debug!("Skipping country list for {} (source disabled)", ip_version);
                continue;
            }

            http_urls.extend(
                generate_country_urls(countries, country_tmpl).inspect(|url| {
                    url_map.insert(url.clone(), (set_name.clone(), ip_version, None));
                }),
            );
        }
    }

    // Start (consume) all downloads. Returns immediately with a receiver
    let rx = start_downloads(pool, http_urls);

    let mut process_result = |result: DownloadResult| match result.source {
        Ok(source) => {
            if let Some((set_name, version, override_prefix)) = url_map.remove(&result.url) {
                let reader: Box<dyn BufRead> = match &source {
                    InputSource::Temp(file) => Box::new(BufReader::new(file)),
                    InputSource::Local(path) => match std::fs::File::open(path) {
                        Ok(f) => Box::new(BufReader::new(f)),
                        Err(e) => {
                            warn!("Failed to open file {}: {}", path.display(), e);
                            return;
                        }
                    },
                };

                if context.verbosity >= 2 {
                    debug!("Processing data for {}", set_name);
                }

                let input = ProcessingInput {
                    source: &result.url,
                    reader,
                    min_prefix: override_prefix.unwrap_or(match version {
                        IpVersion::V4 => cfg.net.v4.min_prefix,
                        IpVersion::V6 => cfg.net.v6.min_prefix,
                    }),
                };

                sets.process_input(version, &set_name, input);
            }
        }
        Err(e) => {
            warn!("Failed to process {}: {}", result.url, e);
        }
    };

    for result in rx {
        process_result(result);
    }

    // Process local files
    for result in process_local_files(file_urls) {
        process_result(result);
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
    let suffix = get_epoch_suffix();
    let sets = collect_ip_sets(context, suffix);

    // Pass "full_config" as the block name
    let generator = |writer: &mut dyn Write| -> Result<()> {
        render_template(context, &sets, writer, "full_config", suffix)
    };

    if context.print_stdout {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        generator(&mut handle)?;
    } else {
        run_nft_stream(context.dry_run, generator)?;
    }
    Ok(())
}

fn stop() -> Result<()> {
    info!("Stopping zuul");
    run_nft_cli(&["delete", "table", "netdev", "blackhole"], false)?;
    info!("Successfully deleted nftables table 'netdev blackhole'");

    Ok(())
}

fn cleanup_old_sets(context: &AppContext, current_suffix: u64) -> Result<()> {
    if context.dry_run {
        debug!("Mocking cleanup of old sets");
        return Ok(());
    }

    debug!("Checking for old sets to clean up");
    let output = run_nft_cli(&["list", "sets", "table", "netdev", "blackhole"], false)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let re = regex::Regex::new(r"set\s+([a-zA-Z0-9_]+)\s+\{").expect("Invalid regex");

    let cfg = &context.config;
    let dynamic_bases = [&cfg.set_names.abuselist, &cfg.set_names.country];

    for cap in re.captures_iter(&stdout) {
        let name = &cap[1];

        // Check if this set belongs to one of our dynamic categories
        let is_dynamic = dynamic_bases
            .iter()
            .any(|base| name.starts_with(&format!("{}_", base)));

        if is_dynamic && !name.ends_with(&format!("_{}", current_suffix)) {
            info!("Deleting old set: {}", name);
            // Ignore errors - set might be in use or already deleted
            let _ = run_nft_cli(
                &["delete", "set", "netdev", "blackhole", name],
                context.dry_run,
            );
        }
    }
    Ok(())
}

fn refresh(context: &AppContext) -> Result<()> {
    info!("Reloading abuselist and country lists");
    let suffix = get_epoch_suffix();
    let sets = collect_ip_sets(context, suffix);

    info!("Applying atomic update with suffix {}", suffix);

    // Combine everything into one single transaction
    let atomic_update = |writer: &mut dyn Write| -> Result<()> {
        // TABLE BEGIN
        // Note: This works in the same stream. nft processes line-by-line in a single transaction
        // context.
        writeln!(writer, "flush chain netdev blackhole validation")?;
        writeln!(writer, "table netdev blackhole {{")?;
        render_template(context, &sets, writer, "sets_dynamic", suffix)?;

        render_template(context, &sets, writer, "chain_validation", suffix)?;
        writeln!(writer, "}}")?;
        // TABLE END

        Ok(())
    };

    if context.print_stdout {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        atomic_update(&mut handle)?;
    } else {
        // This is the most efficient way: one fork, one pipe, one transaction
        run_nft_stream(context.dry_run, atomic_update)?;
    }

    // Step 4: Clean up old sets
    if !context.print_stdout {
        info!("Cleaning up old sets");
        cleanup_old_sets(context, suffix)?;
    }

    let (total_v4, total_v6) = calculate_totals(&sets);
    info!(
        "Reloaded total entries IPv4: {} IPv6: {}",
        total_v4, total_v6
    );
    Ok(())
}

fn run_nft_cli(args: &[&str], dry_run: bool) -> Result<Output> {
    if dry_run {
        debug!("Mocking nft command: nft {}", args.join(" "));
        let mock_status = std::os::unix::process::ExitStatusExt::from_raw(0);
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

// Spawns `nft -f -` and executes the provided callback to write rules to its stdin.
/// Handles broken pipes gracefully (ignoring them if caused by early nft exit)
fn run_nft_stream<F>(dry_run: bool, write_op: F) -> Result<()>
where
    F: FnOnce(&mut dyn Write) -> Result<()>,
{
    if dry_run {
        debug!("Mocking nft command: nft -f -");
        let mut sink = std::io::sink();
        write_op(&mut sink)?;
        return Ok(());
    }

    info!("Executing nft command: nft -f -");
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn nft command")?;

    {
        let stdin = child.stdin.as_mut().context("Failed to open stdin")?;
        let mut writer = std::io::BufWriter::new(stdin);

        if let Err(e) = write_op(&mut writer) {
            // Check for BrokenPipe (nft closed connection early)
            let is_broken_pipe = e.chain().any(|c| {
                c.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
            });

            if !is_broken_pipe {
                return Err(e);
            }
        }
    }

    let output = child.wait_with_output().context("Failed to wait on nft")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("nft command failed: {}", stderr);
        return Err(anyhow::anyhow!("nft execution error: {stderr}"));
    }

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
    let template_path = resolve_fragment(cli.template, "template.j2")?;

    // Landlock init
    #[cfg(feature = "sandbox")]
    match sandbox::harden([&config_path, &template_path, &std::env::current_dir()?]) {
        Ok(sandbox::Status::Full) => info!("Landlock sandbox fully active"),
        Ok(status) if cli.enforce_sandbox => {
            anyhow::bail!("Fatal: Sandbox is enforced but status is: {}", status)
        }
        Ok(status) => warn!("Landlock sandbox is only: `{}`", status),
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

    // Tests for parse_v4_net_bytes
    #[test]
    fn test_parse_v4_net_bytes_with_prefix() {
        let result = parse_v4_net_bytes(b"192.168.1.0/24");
        assert!(result.is_some());

        let net = result.unwrap();
        assert_eq!(net.addr(), std::net::Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(net.prefix_len(), 24);
    }

    #[test]
    fn test_parse_v4_net_bytes_without_prefix() {
        let result = parse_v4_net_bytes(b"192.168.1.1");
        assert!(result.is_some());
        let net = result.unwrap();
        // Should default to /32
        assert_eq!(net.prefix_len(), 32);
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
        assert_eq!(net.prefix_len(), 32);
    }

    #[test]
    fn test_parse_v6_net_bytes_without_prefix() {
        let result = parse_v6_net_bytes(b"::1");

        assert!(result.is_some());
        let net = result.unwrap();
        // Should default to /128
        assert_eq!(net.prefix_len(), 128);
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
            let prefix = cidr::Ipv6Prefix::new(i).unwrap();
            assert_eq!(prefix.as_u8(), i);

            let value: u8 = prefix.into();
            assert_eq!(value, i);
        }
    }

    // Implement PrefixCheck for u32 in tests (stub implementation)
    impl cidr::PrefixCheck for u32 {
        #[inline]
        fn meets_min_prefix(&self, _min: u8) -> bool {
            // For testing purposes, u32 values always "meet" prefix requirements
            true
        }
    }

    // Helper parser for process_ips tests: parses ASCII lines into u32,
    // returns None on invalid input.
    fn parse_u32_bytes(line: &[u8]) -> ParsedResult<u32> {
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

    const MIN_PREFIX_LEN: u8 = 0;
    #[test]
    fn process_ips_inserts_valid_and_skips_invalid() {
        // Use a simple numeric type (u32) for T with a custom parser.
        let mut map = NetSets::<u32>::default();
        // Lines:
        // "1" -> valid
        // "2" -> valid
        // "bad" -> invalid
        // "2" -> duplicate (should not increase set size)
        let content = b"1\n2\nbad\n2\n";
        let source = "memory://test";
        let cursor = Cursor::new(content.to_vec());
        let input = ProcessingInput {
            source,
            reader: cursor,
            min_prefix: MIN_PREFIX_LEN,
        };
        IpSets::merge_into_map(&mut map, "test-set", input, parse_u32_bytes);

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
        let source = "memory://test";
        assert!(!map.contains_key("new-set"));
        let cursor = Cursor::new(content.to_vec());
        let input = ProcessingInput {
            source,
            reader: cursor,
            min_prefix: MIN_PREFIX_LEN,
        };
        IpSets::merge_into_map(&mut map, "new-set", input, parse_u32_bytes);
        let set = map.get("new-set").expect("set should have been created");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&42));
    }

    #[test]
    fn process_ips_ignores_blank_and_comment_lines() {
        let mut map = NetSets::<u32>::default();
        let content = b"\n# full comment\n \t # comment with leading ws\n7\n";
        let source = "memory://test";
        let cursor = Cursor::new(content.to_vec());
        let input = ProcessingInput {
            source,
            reader: cursor,
            min_prefix: MIN_PREFIX_LEN,
        };
        IpSets::merge_into_map(&mut map, "comments", input, parse_u32_bytes);
        let set = map.get("comments").expect("set should exist");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&7));
    }

    #[test]
    fn process_ips_enforces_min_prefix_for_untrusted_source() {
        let mut map = NetSets::<Ipv4Net>::default();
        // Data:
        // 192.168.1.1/32 -> Valid (prefix 32 >= 24)
        // 10.0.0.0/8     -> Invalid (prefix 8 < 24)
        // 172.16.0.0/24  -> Valid (prefix 24 >= 24)
        let content = b"192.168.1.1/32\n10.0.0.0/8\n172.16.0.0/24\n";
        // Untrusted source (does not start with "inline:")
        let source = "https://example.com/bad_ips.txt";
        let input = ProcessingInput {
            source,
            reader: Cursor::new(content.to_vec()),
            min_prefix: 24,
        };
        IpSets::merge_into_map(&mut map, "filter_v4", input, parse_v4_net_bytes);
        let set = map.get("filter_v4").expect("set should exist");
        assert_eq!(set.len(), 2);

        let valid_1 = parse_v4_net_bytes(b"192.168.1.1/32").unwrap();
        assert!(set.contains(&valid_1));

        let valid_2 = parse_v4_net_bytes(b"172.16.0.0/24").unwrap();
        assert!(set.contains(&valid_2));

        let invalid = parse_v4_net_bytes(b"10.0.0.0/8").unwrap();
        assert!(!set.contains(&invalid));
    }

    #[test]
    fn process_ips_allows_short_prefix_for_trusted_source() {
        let mut map = NetSets::<Ipv4Net>::default();
        // 10.0.0.0/8 is usually too short, but should be allowed for trusted
        let content = b"10.0.0.0/8\n";
        // Trusted source (starts with "inline:")
        let source = "inline:whitelist_v4";
        let input = ProcessingInput {
            source,
            reader: Cursor::new(content.to_vec()),
            min_prefix: 24,
        };
        IpSets::merge_into_map(&mut map, "trusted_v4", input, parse_v4_net_bytes);
        let set = map.get("trusted_v4").expect("set should exist");
        assert_eq!(set.len(), 1);

        let net = parse_v4_net_bytes(b"10.0.0.0/8").unwrap();
        assert!(set.contains(&net));
    }

    #[test]
    fn process_ips_handles_large_lines_gracefully() {
        // We can use u32 here for simplicity of data generation,
        // as this test checks buffer logic, not IP parsing.
        let mut map = NetSets::<u32>::default();
        // Create a line larger than PAGE_ALIGNED_SIZE (4096)
        let mut big_line = vec![b'a'; 4097];
        big_line.push(b'\n');
        let valid_line = b"123\n";
        let mut content = big_line;
        content.extend_from_slice(valid_line);
        let input = ProcessingInput {
            source: "memory://overflow",
            reader: Cursor::new(content),
            min_prefix: 0,
        };
        IpSets::merge_into_map(&mut map, "overflow_test", input, parse_u32_bytes);

        let set = map.get("overflow_test").unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set[0], 123);
    }

    #[test]
    fn process_ips_handles_eof_without_newline() {
        let mut map = NetSets::<u32>::default();
        // "999" without a trailing \n
        let content = b"999";
        let input = ProcessingInput {
            source: "memory://eof_no_newline",
            reader: Cursor::new(content.to_vec()),
            min_prefix: 0,
        };
        IpSets::merge_into_map(&mut map, "eof_test", input, parse_u32_bytes);

        let set = map.get("eof_test").unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set[0], 999);
    }

    #[test]
    fn process_ips_discards_lines_exceeding_buffer_limit() {
        let mut map = NetSets::<u32>::default();
        // 1. Create a "Line Too Long": 4096 bytes of 'a's (fills the buffer completely without a
        //    newline). Followed by "1\n" (the "tail" of the long line). Total line length: 4096 + 2
        //    = 4098 bytes.
        let mut content = vec![b'a'; 4096];
        content.extend_from_slice(b"1\n");
        // 2. Add a valid second line "2\n"
        content.extend_from_slice(b"2\n");
        let input = ProcessingInput {
            source: "memory://long_line_test",
            reader: Cursor::new(content),
            min_prefix: 0,
        };
        IpSets::merge_into_map(&mut map, "long_test", input, parse_u32_bytes);
        let set = map.get("long_test").expect("set should be created");

        // "1" must be DISCARDED because it is part of the long line.
        // "2" must be ACCEPTED because the buffer was cleared and recovery was successful.
        assert_eq!(set.len(), 1);
        assert!(set.contains(&2));
        assert!(!set.contains(&1));
    }

    #[test]
    fn process_ips_accepts_lines_at_exact_buffer_limit() {
        let mut map = NetSets::<u32>::default();
        // Create a line exactly 4096 bytes long (the buffer limit).
        // 4094 spaces + "1" + "\n" = 4096 bytes.
        // This is a valid line that fills the buffer exactly.
        let mut content = vec![b' '; 4094];
        content.push(b'1');
        content.push(b'\n');
        let input = ProcessingInput {
            source: "memory://boundary_test",
            reader: Cursor::new(content),
            min_prefix: 0,
        };
        IpSets::merge_into_map(&mut map, "boundary_test", input, parse_u32_bytes);
        let set = map.get("boundary_test").expect("set should be created");

        // Should NOT be discarded.
        // Trimming removes the 4094 spaces, leaving "1".
        assert_eq!(set.len(), 1);
        assert!(set.contains(&1));
    }

    #[test]
    fn process_ips_deduplicates_and_sorts() {
        // Verify deduplication logic works for IpNets too
        let mut map = NetSets::<Ipv4Net>::default();
        // 1.1.1.1, 8.8.8.8, 1.1.1.1 (dup)
        let content = b"1.1.1.1\n8.8.8.8\n1.1.1.1\n";
        let input = ProcessingInput {
            source: "memory://dedup",
            reader: Cursor::new(content.to_vec()),
            min_prefix: 0,
        };
        IpSets::merge_into_map(&mut map, "dedup_v4", input, parse_v4_net_bytes);
        let set = map.get("dedup_v4").unwrap();
        assert_eq!(set.len(), 2);

        // Verify sorted order
        let ip1 = parse_v4_net_bytes(b"1.1.1.1").unwrap();
        let ip2 = parse_v4_net_bytes(b"8.8.8.8").unwrap();
        assert_eq!(set[0], ip1);
        assert_eq!(set[1], ip2);
    }

    #[test]
    fn test_lazy_ip_set_formatting_multiple() {
        let set = vec!["10.0.0.0/8".to_owned(), "192.168.0.0/16".to_owned()];
        // Insert strings (LazyIpSet is generic over T: Display)
        let lazy = LazyIpSet {
            data: Arc::new(set),
            set_type: SetType::Static,
        };

        // Verify formatting matches the template expectation
        let expected = "10.0.0.0/8,\n\t\t192.168.0.0/16";
        assert_eq!(lazy.to_string(), expected);
    }

    #[test]
    fn test_lazy_ip_set_formatting_single() {
        let set = vec!["10.0.0.0/8".to_owned()];
        let lazy = LazyIpSet {
            data: Arc::new(set),
            set_type: SetType::Static,
        };
        assert_eq!(lazy.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_lazy_ip_set_formatting_empty() {
        let set = NetSet::<String>::new();
        let lazy = LazyIpSet {
            data: Arc::new(set),
            set_type: SetType::Static,
        };
        assert_eq!(lazy.to_string(), "");
    }

    #[test]
    fn test_lazy_ip_set_truthiness() {
        use minijinja::value::Object;

        let set = vec!["item".to_owned()];
        let not_empty = Arc::new(LazyIpSet {
            data: Arc::new(set),
            set_type: SetType::Static,
        });
        assert!(Object::is_true(&not_empty));

        let empty = Arc::new(LazyIpSet {
            data: Arc::new(NetSet::<String>::new()),
            set_type: SetType::Static,
        });
        assert!(!Object::is_true(&empty));
    }
}
