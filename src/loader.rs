// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Cursor, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result};
use tracing::{debug, info, trace, warn};

use crate::{
    AppContext,
    config::{IpVersion, ListEntry},
    istr::IStr,
    sets::SetInventory,
    threadpool::ThreadPool,
};

pub struct ProcessingInput<'a, R> {
    pub source: &'a str,
    pub reader: R,
    pub min_prefix: u8,
    pub trusted: bool,
}

#[derive(Debug, Clone)]
pub struct DownloadJob {
    pub url: IStr,
}

#[derive(Debug)]
pub struct DownloadResult {
    pub url: IStr,
    pub(crate) source: Result<InputSource>,
}

#[derive(Debug)]
pub enum InputSource {
    Temp(tempfile::NamedTempFile),
    Local(PathBuf),
}

#[derive(Debug)]
pub enum UrlEntry {
    Http {
        url: IStr,
        min_prefix: Option<u8>,
        trusted: bool,
    },
    File {
        path: IStr,
        min_prefix: Option<u8>,
        trusted: bool,
    },
}

impl UrlEntry {
    /// Checks for configuration inconsistencies and warns if found
    pub fn validate_config(&self) {
        let (resource, min_prefix, trusted) = match self {
            Self::Http {
                url,
                min_prefix,
                trusted,
            } => (url, min_prefix, trusted),
            Self::File {
                path,
                min_prefix,
                trusted,
            } => (path, min_prefix, trusted),
        };

        if *trusted && min_prefix.is_some() {
            warn!(
                "Configuration warning for {}: `trusted: true` bypasses prefix validation, so \
                 `min_prefix: {}` will be IGNORED.",
                resource,
                min_prefix.unwrap()
            );
        }
    }

    #[inline]
    #[must_use]
    pub const fn resource(&self) -> &IStr {
        match self {
            Self::Http { url, .. } => url,
            Self::File { path, .. } => path,
        }
    }
}

// Convenience constructor for downloads
impl ThreadPool<DownloadJob, DownloadResult> {
    // Convenience constructor for downloads
    pub fn downloader(size: usize, timeout: u64) -> Self {
        Self::new(
            size.try_into().expect("Pool size must be > 0"),
            move |job| download_url(timeout, job),
        )
    }
}

// Returns a Receiver that yields results as they finish
pub fn start_downloads(
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

pub fn process_local_files<I, S>(urls: I) -> impl Iterator<Item = DownloadResult>
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

fn parse_list_entries<S: AsRef<str>>(
    entries: &[ListEntry],
    tmpl_urls: &[S],
    default_trust: bool, // Pass the list-specific default here
) -> (Vec<UrlEntry>, String) {
    let mut urls = Vec::with_capacity(entries.len());
    let mut inline_buf = String::new();

    for entry in entries {
        let (raw_str, custom_prefix, custom_trust) = entry.as_parts();
        let trimmed = raw_str.trim();

        // Resolve trust: Entry override OR List default
        let is_trusted = custom_trust.unwrap_or(default_trust);

        if trimmed.starts_with("https://") {
            urls.push(UrlEntry::Http {
                url: IStr::from(trimmed),
                min_prefix: custom_prefix,
                trusted: is_trusted,
            });
        } else if trimmed.starts_with("file://") {
            urls.push(UrlEntry::File {
                path: IStr::from(trimmed),
                min_prefix: custom_prefix,
                trusted: is_trusted,
            });
        } else if trimmed.len() >= 2
            && trimmed[..2].eq_ignore_ascii_case("as")
            && trimmed[2..].chars().all(|c| c.is_ascii_digit())
        {
            let digits = &trimmed[2..];
            if tmpl_urls.is_empty() {
                warn!("Skipping ASN entry {} (no source URLs configured)", trimmed);
            } else {
                debug!("Processing ASN entry: AS{}", digits);
                urls.extend(tmpl_urls.iter().map(|tmpl| UrlEntry::Http {
                    url: IStr::from(tmpl.as_ref().replace("{asn}", digits)),
                    min_prefix: custom_prefix,
                    trusted: is_trusted,
                }));
            }
        } else {
            // Direct IPs are always trusted
            if !inline_buf.is_empty() {
                inline_buf.push('\n');
            }
            inline_buf.push_str(trimmed);
        }
    }
    (urls, inline_buf)
}

#[derive(Debug, Clone)]
struct SetContext {
    set_name: IStr,
    version: IpVersion,
    min_prefix: Option<u8>,
    trusted: bool,
}

pub fn collect_ip_sets(context: &AppContext) -> SetInventory {
    let cfg = &context.config;
    let mut sets = SetInventory::new();
    let pool = Arc::new(ThreadPool::downloader(context.threads, context.timeout));

    // Map URL to (set_name, version, override_prefix, is_trusted)
    let mut url_map: HashMap<IStr, SetContext> = HashMap::new();
    let mut http_urls = Vec::new();
    let mut file_urls = Vec::new();

    for ip_version in cfg.net.get_active() {
        let global_min_prefix = match ip_version {
            IpVersion::V4 => cfg.net.v4.min_prefix,
            IpVersion::V6 => cfg.net.v6.min_prefix,
        };
        let asn_tmpl = cfg.sources.asn.get(ip_version);

        // Define default trust levels
        let lists = [
            (&cfg.whitelist, &cfg.set_names.whitelist, true),
            (&cfg.blacklist, &cfg.set_names.blacklist, true),
            (&cfg.abuselist, &cfg.set_names.abuselist, false),
        ];

        for (maybe_list, base_name, default_trust) in lists {
            if let Some(entries) = maybe_list.as_ref().and_then(|m| m.get(&ip_version)) {
                let set_name = IStr::from(format!("{}_{}", base_name, ip_version));

                // Parse entries (separating inline Nets from URLs)
                // We pass the default_trust here so the parser can resolve the final boolean for
                // each URL
                let (parsed_urls, raw_content) =
                    parse_list_entries(entries, asn_tmpl, default_trust);

                // Process Inline Nets (Always trusted)
                if !raw_content.is_empty() {
                    let input = ProcessingInput {
                        source: &format!("static:{}", set_name.to_ascii_uppercase()),
                        reader: Cursor::new(raw_content.into_bytes()),
                        min_prefix: global_min_prefix,
                        trusted: true,
                    };
                    let _ = sets.dispatch_protocol_parser(ip_version, &set_name, input);
                }

                for entry in parsed_urls {
                    entry.validate_config();

                    let key = entry.resource().clone();

                    let (min_prefix, trusted) = match entry {
                        UrlEntry::Http {
                            min_prefix,
                            trusted,
                            url,
                            ..
                        } => {
                            http_urls.push(url);
                            (min_prefix, trusted)
                        }
                        UrlEntry::File {
                            min_prefix,
                            trusted,
                            path,
                            ..
                        } => {
                            file_urls.push(path);
                            (min_prefix, trusted)
                        }
                    };

                    // 3. Use the common data for the map insertion
                    url_map.insert(
                        key,
                        SetContext {
                            set_name: set_name.clone(),
                            version: ip_version,
                            min_prefix,
                            trusted,
                        },
                    );
                }
            }
        }

        // Country List Processing
        if let Some(countries) = &cfg.country_list {
            let set_name = IStr::from(format!("{}_{}", cfg.set_names.country, ip_version));
            let country_tmpl = cfg.sources.country.get(ip_version);

            if country_tmpl.is_empty() {
                debug!("Skipping country list for {} (source disabled)", ip_version);
            } else {
                http_urls.extend(
                    generate_country_urls(countries, country_tmpl).inspect(|url| {
                        // Country lists are typically external sources, so we default to untrusted
                        // (false) They usually contain valid CIDRs, but
                        // prefix checking is safer.
                        url_map.insert(
                            url.clone(),
                            SetContext {
                                set_name: set_name.clone(),
                                version: ip_version,
                                min_prefix: None,
                                trusted: false,
                            },
                        );
                    }),
                );
            }
        }
    }

    // Start downloads
    let rx = start_downloads(pool, http_urls);

    let mut process_result = |result: DownloadResult| match result.source {
        Ok(source) => {
            if let Some(ctx) = url_map.remove(&result.url) {
                let reader: Box<dyn BufRead + Send> = match &source {
                    InputSource::Temp(file) => Box::new(BufReader::new(file)),
                    InputSource::Local(path) => match std::fs::File::open(path) {
                        Ok(f) => Box::new(BufReader::new(f)),
                        Err(e) => {
                            warn!("Failed to open file {}: {}", path.display(), e);
                            return;
                        }
                    },
                };

                let global_min_prefix = match ctx.version {
                    IpVersion::V4 => cfg.net.v4.min_prefix,
                    IpVersion::V6 => cfg.net.v6.min_prefix,
                };

                if context.verbosity >= 2 {
                    debug!("Processing data for {}", ctx.set_name);
                }

                let input = ProcessingInput {
                    source: &result.url,
                    reader,
                    min_prefix: ctx.min_prefix.unwrap_or(global_min_prefix),
                    trusted: ctx.trusted,
                };
                let _ = sets.dispatch_protocol_parser(ctx.version, &ctx.set_name, input);
            }
        }
        Err(e) => {
            warn!("Failed to process {}: {}", result.url, e);
        }
    };

    // Consume results
    for result in rx {
        process_result(result);
    }

    // Process local files
    for result in process_local_files(file_urls) {
        process_result(result);
    }

    let (total_v4, total_v6) = sets.log_totals();
    info!(
        "Total entries IPv4: {} IPv6: {} total: {}",
        total_v4,
        total_v6,
        total_v4 + total_v6
    );

    sets
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn test_parse_list_entries_mixed_content() {
        let entries = vec![
            ListEntry::Simple("AS12345".to_owned()),
            ListEntry::Simple("https://example.com/list".to_owned()),
            ListEntry::Simple("10.0.0.0/8".to_owned()),
        ];
        let templates = ["https://api.example.com/asn/{asn}"];

        // Use default_trust = false (abuselist behavior)
        let (urls, raw) = parse_list_entries(&entries, &templates, false);

        assert_eq!(urls.len(), 2);

        // Check ASN expansion (should be Untrusted)
        let asn_entry = urls.iter().find(
            |u| matches!(u, UrlEntry::Http { url, trusted: false, .. } if url.contains("12345")),
        );
        assert!(asn_entry.is_some(), "ASN should be expanded to URL");

        // Check HTTP URL (should be Untrusted)
        let http_entry = urls.iter().find(|u| matches!(u, UrlEntry::Http { url, trusted: false, .. } if url.contains("example.com/list")));
        assert!(http_entry.is_some(), "Standard URL should be preserved");

        // Check Raw Content (Always Trusted implicitly by being returned in the string)
        assert!(
            raw.contains("10.0.0.0/8"),
            "Raw IP should be in the string buffer"
        );
    }

    #[test]
    fn test_parse_list_entries_trusted_override() {
        let entries = vec![
            // Detailed entry explicitly setting trusted = true
            ListEntry::Detailed {
                url: "https://trusted.com/list".into(),
                min_prefix: None,
                trusted: Some(true),
            },
        ];
        let templates: &[&str] = &[];

        // Use default_trust = false
        let (urls, _) = parse_list_entries(&entries, templates, false);

        assert_eq!(urls.len(), 1);
        if let UrlEntry::Http { trusted, .. } = &urls[0] {
            assert!(*trusted, "Detailed entry should override default trust");
        } else {
            panic!("Expected Http entry");
        }
    }

    #[test]
    fn test_collect_ip_sets_local_files() {
        use std::{collections::HashMap, path::PathBuf};

        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let test_file = project_root.join("tests/testdata/ipv4-test.netset");

        // Ensure the test file actually exists before trying to load it
        assert!(
            test_file.exists(),
            "Test file not found at: {}",
            test_file.display()
        );

        let file_url = format!("file://{}", test_file.display());

        // Mock config
        let mut config = crate::config::Config {
            net: crate::config::IpConfigs::default(),
            default_policy: Cow::Borrowed("accept"),
            block_policy: Cow::Borrowed("drop"),
            iifname: vec![Cow::Borrowed("lo")],
            set_names: crate::config::SetNames::default(),
            logging: crate::config::LogConfig::default(),
            sources: crate::config::Sources::default(),
            whitelist: None,
            blacklist: None,
            abuselist: None,
            country_list: None,
        };

        let mut v4_map = HashMap::new();
        v4_map.insert(IpVersion::V4, vec![ListEntry::Simple(file_url)]);
        // abuselist only
        config.abuselist = Some(v4_map);

        // 4. Setup: AppContext
        let context = crate::AppContext {
            config,
            template: project_root.join("template.j2"),
            timeout: 1,
            threads: 1,
            verbosity: 0,
            dry_run: true,
            print_stdout: false,
        };

        let inventory = collect_ip_sets(&context);
        let v4_sets = &inventory.v4_sets;
        let set_name = IStr::from("abuselist_v4");

        if let Some(set) = v4_sets.get(&set_name) {
            assert!(!set.is_empty(), "Set should not be empty");
            assert!(set.len() == 90, "Set should contain 90 entries");
            let net = "223.4.0.0/14";
            let expected = net.parse::<ipnet::Ipv4Net>().unwrap();
            assert!(set.contains(&expected), "Expected set to contain {}", net);
        } else {
            panic!(
                "Set {} was not found. Available sets: {:?}",
                set_name,
                v4_sets.keys()
            );
        }
    }
}
