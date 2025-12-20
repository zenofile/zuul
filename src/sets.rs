// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::{
    collections::HashMap,
    hint::{cold_path, likely, unlikely},
    io::BufRead,
    sync::Arc,
};

use anyhow::Result;
use ipnet::{Ipv4Net, Ipv6Net};
use tracing::{debug, error, info, warn};

use crate::{cidr, config::IpVersion, istr::IStr, loader::ProcessingInput};

// BTreeMap is just too slow, sorry
pub type NetSet<T> = Vec<T>;
pub type NetSets<T> = HashMap<IStr, Arc<NetSet<T>>>;

#[derive(Debug)]
pub struct SetInventory {
    pub v4_sets: NetSets<Ipv4Net>,
    pub v6_sets: NetSets<Ipv6Net>,
}

impl SetInventory {
    #[must_use]
    pub fn new() -> Self {
        Self {
            v4_sets: HashMap::new(),
            v6_sets: HashMap::new(),
        }
    }

    pub fn dispatch_protocol_parser<R: BufRead>(
        &mut self,
        version: IpVersion,
        set_name: &str,
        input: ProcessingInput<R>,
    ) -> Result<()> {
        match version {
            IpVersion::V4 => {
                self.v4_sets
                    .import_from_source(set_name, input, cidr::parse_v4_net_bytes)
            }
            IpVersion::V6 => {
                self.v6_sets
                    .import_from_source(set_name, input, cidr::parse_v6_net_bytes)
            }
        }
    }

    #[inline]
    #[must_use]
    pub fn log_totals(&self) -> (usize, usize) {
        #[inline]
        fn count_ips<T>(sets: &NetSets<T>, version: &str) -> usize {
            sets.iter()
                .inspect(|(name, set)| {
                    info!("Set {}: {} unique {} networks", name, set.len(), version);
                })
                .map(|(_, set)| set.len())
                .sum()
        }

        (
            count_ips(&self.v4_sets, "IPv4"),
            count_ips(&self.v6_sets, "IPv6"),
        )
    }
}

pub trait IpSetImporter<T> {
    fn import_from_source<R, F>(
        &mut self,
        set_name: &str,
        input: ProcessingInput<R>,
        parser: F,
    ) -> anyhow::Result<()>
    where
        R: std::io::BufRead,
        F: Fn(&[u8]) -> cidr::ParsedResult<T>;
}

impl<T> IpSetImporter<T> for NetSets<T>
where
    T: Ord + Copy + std::fmt::Debug + cidr::PrefixCheck + Send + Sync + 'static,
{
    fn import_from_source<R, F>(
        &mut self,
        set_name: &str,
        mut input: ProcessingInput<R>,
        parser: F,
    ) -> anyhow::Result<()>
    where
        R: std::io::BufRead,
        F: Fn(&[u8]) -> cidr::ParsedResult<T>,
    {
        let trusted_set = input.trusted;
        let mut invalid = 0;
        const PAGE_ALIGNED_SIZE: usize = 4096;

        let mut line_buf = Vec::with_capacity(PAGE_ALIGNED_SIZE >> 2);
        let mut batch_buf = Vec::with_capacity(PAGE_ALIGNED_SIZE);

        loop {
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

            // Check for line length overflow
            if unlikely(bytes_read as u64 == PAGE_ALIGNED_SIZE as u64)
                && line_buf.last() != Some(&b'\n')
            {
                warn!("Line too long in {}, discarding", input.source);
                discard_line(&mut input.reader, Some(input.source));
                continue;
            }

            let line_bytes = strip_comment_and_trim_bytes(&line_buf);
            if line_bytes.is_empty() {
                continue;
            }

            if let Some(net) = parser(line_bytes) {
                if likely(trusted_set || net.meets_min_prefix(input.min_prefix)) {
                    batch_buf.push(net);
                } else {
                    warn!(
                        "Skipping non-trusted IP range {} (invalid prefix)",
                        String::from_utf8_lossy(line_bytes)
                    );
                    invalid += 1;
                }
            } else {
                cold_path();
                invalid += 1;
                if tracing::level_enabled!(tracing::Level::DEBUG) {
                    debug!(
                        "Invalid IP entry: {}",
                        String::from_utf8_lossy(&line_bytes[..line_bytes.len().min(0x32)])
                    );
                }
            }
        }

        let set = Arc::make_mut(self.entry(IStr::from(set_name)).or_default());

        let old_len = set.len();
        set.extend(batch_buf);
        set.sort_unstable();

        let (unique, _duplicates) = set.partition_dedup();
        let new_len = unique.len();
        let added = new_len - old_len;
        set.truncate(new_len);

        log_results(set_name, input.source, added, invalid);

        Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetType {
    Static,
    Dynamic,
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ipnet::Ipv4Net;

    use super::*;
    use crate::cidr::{ParsedResult, PrefixCheck, parse_v4_net_bytes};

    // Tests for strip_comment_and_trim_bytes
    #[test]
    fn strip_comment_trims_whitespace_only() {
        let line = b"   \t  example.com  \t ";
        let out = strip_comment_and_trim_bytes(line);
        assert_eq!(out, b"example.com");
    }

    #[test]
    fn strip_comment_removes_trailing_comment() {
        let line = b"10.0.0.0/8   # private v4 range";
        let out = strip_comment_and_trim_bytes(line);
        assert_eq!(out, b"10.0.0.0/8");
    }

    #[test]
    fn strip_comment_handles_only_comment_line() {
        let line = b"# just a comment";
        let out = strip_comment_and_trim_bytes(line);
        assert!(out.is_empty());
    }

    #[test]
    fn strip_comment_handles_empty_and_whitespace_lines() {
        let line1 = b"";
        let line2 = b"   \t   ";
        assert!(strip_comment_and_trim_bytes(line1).is_empty());
        assert!(strip_comment_and_trim_bytes(line2).is_empty());
    }

    #[test]
    fn strip_comment_handles_crlf_newlines() {
        let line = b"192.168.0.0/16\r\n# comment";
        // Function sees only the line bytes; simulate a single logical line.
        let out = strip_comment_and_trim_bytes(line);
        assert_eq!(out, b"192.168.0.0/16");
    }

    // Implement PrefixCheck for u32 in tests (stub implementation)
    impl PrefixCheck for u32 {
        #[inline]
        fn meets_min_prefix(&self, _min: u8) -> bool {
            // For testing purposes, u32 values always "meet" prefix requirements
            true
        }
    }
    // Tests for IpSets::new
    #[test]
    fn new_starts_with_empty_maps() {
        let sets = SetInventory::new();
        assert!(sets.v4_sets.is_empty());
        assert!(sets.v6_sets.is_empty());
    }

    // Helper parser for process_ips tests: parses ASCII lines into u32,
    // returns None on invalid input.
    fn parse_u32_bytes(line: &[u8]) -> ParsedResult<u32> {
        std::str::from_utf8(line).ok()?.parse::<u32>().ok()
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
            trusted: false,
        };
        _ = map.import_from_source("test-set", input, parse_u32_bytes);

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
            trusted: false,
        };
        _ = map.import_from_source("new-set", input, parse_u32_bytes);
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
            trusted: false,
        };
        _ = map.import_from_source("comments", input, parse_u32_bytes);
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
            trusted: false,
        };
        _ = map.import_from_source("filter_v4", input, parse_v4_net_bytes);
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
            trusted: true,
        };
        _ = map.import_from_source("trusted_v4", input, parse_v4_net_bytes);
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
            trusted: false,
        };
        _ = map.import_from_source("overflow_test", input, parse_u32_bytes);

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
            trusted: false,
        };
        _ = map.import_from_source("eof_test", input, parse_u32_bytes);

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
            trusted: false,
        };
        _ = map.import_from_source("long_test", input, parse_u32_bytes);
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
            trusted: false,
        };
        _ = map.import_from_source("boundary_test", input, parse_u32_bytes);
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
            trusted: false,
        };
        _ = map.import_from_source("dedup_v4", input, parse_v4_net_bytes);
        let set = map.get("dedup_v4").unwrap();
        assert_eq!(set.len(), 2);

        // Verify sorted order
        let ip1 = parse_v4_net_bytes(b"1.1.1.1").unwrap();
        let ip2 = parse_v4_net_bytes(b"8.8.8.8").unwrap();
        assert_eq!(set[0], ip1);
        assert_eq!(set[1], ip2);
    }
}
