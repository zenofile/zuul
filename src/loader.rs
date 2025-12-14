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
    Http { url: IStr, min_prefix: Option<u8> },
    File { path: IStr, min_prefix: Option<u8> },
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

pub fn collect_ip_sets(context: &AppContext) -> SetInventory {
    let cfg = &context.config;
    let mut sets = SetInventory::new();
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

            let _ = sets.dispatch_protocol_parser(ip_version, &set_name, input);
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

            let _ = sets.dispatch_protocol_parser(ip_version, &set_name, input);
        }

        // Prepare retrieval of remote content
        // Abuselist
        if let Some(entries) = cfg.abuselist.as_ref().and_then(|m| m.get(&ip_version)) {
            let set_name = IStr::from(format!("{}_{}", cfg.set_names.abuselist, ip_version));
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
            let set_name = IStr::from(format!("{}_{}", cfg.set_names.country, ip_version));
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

                let _ = sets.dispatch_protocol_parser(version, &set_name, input);
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn test_generate_abuselist_urls() {
        let entries = vec![
            ListEntry::Simple("AS12345".to_owned()),
            ListEntry::Simple("https://example.com/list".to_owned()),
        ];
        let templates = ["https://api.example.com/asn/{asn}"];
        let urls = generate_abuselist_urls(&entries, &templates);
        assert_eq!(urls.len(), 2);

        let generated = urls
            .iter()
            .find(|u| matches!(u, UrlEntry::Http { url, .. } if url.contains("12345")));
        assert!(generated.is_some());
    }

    #[test]
    fn test_generate_country_urls() {
        // Mixed case to test lowercase logic
        let countries = vec!["US".to_string(), "de".to_string()];
        let templates = [
            "https://example.com/country/{country}.txt",
            "file:///opt/lists/{country}_v4.net",
        ];
        let urls: Vec<_> = generate_country_urls(&countries, &templates)
            .map(|s| s.to_string())
            .collect();

        // Expect 4 URLs: 2 countries * 2 templates
        assert_eq!(urls.len(), 4);
        // Verify order (Outer loop: Country, Inner loop: Template)
        // 1. US -> Template 1
        assert_eq!(urls[0], "https://example.com/country/us.txt");
        // 2. US -> Template 2
        assert_eq!(urls[1], "file:///opt/lists/us_v4.net");
        // 3. de -> Template 1
        assert_eq!(urls[2], "https://example.com/country/de.txt");
    }

    #[test]
    fn test_collect_ip_sets_local_files() {
        use std::{collections::HashMap, path::PathBuf};

        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let test_file = project_root.join("test/ipv4-test.netset");

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
