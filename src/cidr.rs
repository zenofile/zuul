// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

/// CIDR parsing from ascii since ipnet only supports &str
#[derive(Debug, Clone, Copy)]
pub struct InvalidPrefix;

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Prefix(u8);

impl Ipv4Prefix {
    #[must_use]
    pub fn new(val: u8) -> Option<Self> {
        (val <= 32).then_some(Self(val))
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    #[must_use]
    pub fn to_netmask(self) -> std::net::Ipv4Addr {
        let shift = 32 - self.0;
        let mask = (!0u32).checked_shl(shift.into()).unwrap_or(0);
        std::net::Ipv4Addr::from(mask)
    }
}

impl From<Ipv4Prefix> for u8 {
    fn from(prefix: Ipv4Prefix) -> Self {
        prefix.0
    }
}

impl TryFrom<&[u8]> for Ipv4Prefix {
    type Error = InvalidPrefix;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let val = parse_raw_prefix(bytes, 32).ok_or(InvalidPrefix)?;
        Ok(Self(val))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Prefix(u8);

impl Ipv6Prefix {
    #[must_use]
    pub fn new(val: u8) -> Option<Self> {
        (val <= 128).then_some(Self(val))
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<Ipv6Prefix> for u8 {
    fn from(prefix: Ipv6Prefix) -> Self {
        prefix.0
    }
}

impl TryFrom<&[u8]> for Ipv6Prefix {
    type Error = InvalidPrefix;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let val = parse_raw_prefix(bytes, 128).ok_or(InvalidPrefix)?;
        Ok(Self(val))
    }
}

#[inline]
#[must_use]
fn parse_raw_prefix(bytes: &[u8], max: u8) -> Option<u8> {
    if bytes.is_empty() || bytes.len() > 3 {
        return None;
    }

    bytes
        .iter()
        .try_fold(0u8, |acc, &b| {
            if b.is_ascii_digit() {
                acc.checked_mul(10)?.checked_add(b - b'0')
            } else {
                None
            }
        })
        .filter(|&num| num <= max)
}

pub trait PrefixCheck {
    #[allow(dead_code)]
    const MIN_PREFIX_LEN_V4: u8 = 8;
    #[allow(dead_code)]
    const MIN_PREFIX_LEN_V6: u8 = 16;

    fn meets_min_prefix(&self, min: u8) -> bool;
}

impl PrefixCheck for ipnet::Ipv4Net {
    #[inline]
    fn meets_min_prefix(&self, min: u8) -> bool {
        assert!(min <= 32, "Minimum prefix for v4 <= 32");
        self.prefix_len() >= min
    }
}

impl PrefixCheck for ipnet::Ipv6Net {
    #[inline]
    fn meets_min_prefix(&self, min: u8) -> bool {
        assert!(min <= 128, "Minimum prefix for v6 <= 128");
        self.prefix_len() >= min
    }
}

mod prefix_parser {
    use ipnet::{Ipv4Net, Ipv6Net};

    use crate::cidr::{Ipv4Prefix, Ipv6Prefix};

    pub type ParsedResult<T> = Option<T>;

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn parse_v4_net_bytes(input: &[u8]) -> ParsedResult<Ipv4Net> {
        let (ip_bytes, prefix) = match input.split_once(|&b| b == b'/') {
            Some((ip, p)) => (
                ip,
                Ipv4Prefix::try_from(p)
                    .inspect_err(|e| tracing::warn!("Failed to parse v4 prefix: {:?}", e))
                    .ok()?,
            ),
            // Default is /32 for IPv4
            None => (input, Ipv4Prefix::new(32).unwrap()),
        };

        let ip = std::net::Ipv4Addr::parse_ascii(ip_bytes).ok()?;
        let net = Ipv4Net::new(ip, prefix.as_u8()).unwrap();

        Some(net)
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn parse_v6_net_bytes(input: &[u8]) -> ParsedResult<Ipv6Net> {
        let (ip_bytes, prefix) = match input.split_once(|&b| b == b'/') {
            Some((ip, p)) => (
                ip,
                Ipv6Prefix::try_from(p)
                    .inspect_err(|e| tracing::warn!("Failed to parse v6 prefix: {:?}", e))
                    .ok()?,
            ),
            // Default is /128 for IPv6
            None => (input, Ipv6Prefix::new(128)?),
        };

        let ip = std::net::Ipv6Addr::parse_ascii(ip_bytes).ok()?;
        let net = Ipv6Net::new(ip, prefix.as_u8()).unwrap();

        Some(net)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        macro_rules! assert_v4 {
            ($input:expr, $expected_ip:expr, $expected_prefix:expr) => {
                let result = parse_v4_net_bytes($input).expect("Should parse valid v4");
                assert_eq!(result.addr().to_string(), $expected_ip, "IP mismatch");
                assert_eq!(result.prefix_len(), $expected_prefix, "Prefix mismatch");
            };
        }

        macro_rules! assert_v6 {
            ($input:expr, $expected_ip:expr, $expected_prefix:expr) => {
                let result = parse_v6_net_bytes($input).expect("Should parse valid v6");
                assert_eq!(result.addr().to_string(), $expected_ip, "IP mismatch");
                assert_eq!(result.prefix_len(), $expected_prefix, "Prefix mismatch");
            };
        }

        #[test]
        fn test_parse_v4_with_explicit_prefix() {
            // "192.168.1.10/24"
            let input = b"192.168.1.10/24";
            assert_v4!(input, "192.168.1.10", 24);
        }

        #[test]
        fn test_parse_v4_defaults_to_32() {
            // "10.0.0.1" -> Should become /32
            let input = b"10.0.0.1";
            assert_v4!(input, "10.0.0.1", 32);
        }

        #[test]
        fn test_parse_v4_invalid_ip_returns_none() {
            // Malformed IP
            let input = b"999.999.999.999";
            assert!(parse_v4_net_bytes(input).is_none());

            // Garbage
            let input = b"not-an-ip";
            assert!(parse_v4_net_bytes(input).is_none());

            // Empty
            let input = b"";
            assert!(parse_v4_net_bytes(input).is_none());
        }

        #[test]
        fn test_parse_v4_invalid_prefix_returns_none() {
            // Assuming Ipv4Prefix::try_from fails on > 32 or garbage
            let input = b"192.168.1.1/33";
            assert!(parse_v4_net_bytes(input).is_none());

            let input = b"192.168.1.1/abc";
            assert!(parse_v4_net_bytes(input).is_none());
        }

        #[test]
        fn test_parse_v6_with_explicit_prefix() {
            // "fd00::1/64"
            let input = b"fd00::1/64";
            assert_v6!(input, "fd00::1", 64);
        }

        #[test]
        fn test_parse_v6_defaults_to_128() {
            // "::1" -> Should become /128
            let input = b"::1";
            assert_v6!(input, "::1", 128);
        }

        #[test]
        fn test_parse_v6_full_address() {
            let input = b"2001:0db8:85a3:0000:0000:8a2e:0370:7334/64";
            assert_v6!(input, "2001:db8:85a3::8a2e:370:7334", 64);
        }

        #[test]
        fn test_parse_v6_invalid_ip_returns_none() {
            let input = b"zz::1";
            assert!(parse_v6_net_bytes(input).is_none());
        }

        #[test]
        fn test_parse_v6_invalid_prefix_returns_none() {
            // Assuming Ipv6Prefix::try_from fails on > 128
            let input = b"fd00::1/129";
            assert!(parse_v6_net_bytes(input).is_none());
        }

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
    }
}

pub use self::prefix_parser::*;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::{Ipv4Net, Ipv6Net};

    use super::*;

    #[test]
    fn test_ipv4_prefix_new_valid() {
        assert!(Ipv4Prefix::new(0).is_some());
        assert!(Ipv4Prefix::new(24).is_some());
        assert!(Ipv4Prefix::new(32).is_some());
    }

    #[test]
    fn test_ipv4_prefix_new_invalid() {
        assert!(Ipv4Prefix::new(33).is_none());
        assert!(Ipv4Prefix::new(100).is_none());
        assert!(Ipv4Prefix::new(255).is_none());
    }

    #[test]
    fn test_ipv4_prefix_as_u8() {
        let prefix = Ipv4Prefix::new(24).unwrap();
        assert_eq!(prefix.as_u8(), 24);
    }

    #[test]
    fn test_ipv4_prefix_to_netmask() {
        // /24 -> 255.255.255.0
        let prefix = Ipv4Prefix::new(24).unwrap();
        assert_eq!(
            prefix.to_netmask(),
            std::net::Ipv4Addr::new(255, 255, 255, 0)
        );

        // /32 -> 255.255.255.255
        let prefix = Ipv4Prefix::new(32).unwrap();
        assert_eq!(prefix.to_netmask(), Ipv4Addr::BROADCAST);

        // /0 -> 0.0.0.0
        let prefix = Ipv4Prefix::new(0).unwrap();
        assert_eq!(prefix.to_netmask(), Ipv4Addr::UNSPECIFIED);

        // /8 -> 255.0.0.0
        let prefix = Ipv4Prefix::new(8).unwrap();
        assert_eq!(prefix.to_netmask(), Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn test_ipv4_prefix_into_u8() {
        let prefix = Ipv4Prefix::new(16).unwrap();
        let value: u8 = prefix.into();
        assert_eq!(value, 16);
    }

    #[test]
    fn test_ipv4_prefix_try_from_bytes_valid() {
        assert!(Ipv4Prefix::try_from(b"0" as &[u8]).is_ok());
        assert!(Ipv4Prefix::try_from(b"24" as &[u8]).is_ok());
        assert!(Ipv4Prefix::try_from(b"32" as &[u8]).is_ok());
    }

    #[test]
    fn test_ipv4_prefix_try_from_bytes_invalid() {
        assert!(Ipv4Prefix::try_from(b"33" as &[u8]).is_err());
        assert!(Ipv4Prefix::try_from(b"-1" as &[u8]).is_err());
        assert!(Ipv4Prefix::try_from(b"abc" as &[u8]).is_err());
        assert!(Ipv4Prefix::try_from(b"" as &[u8]).is_err());
    }

    // Tests for PrefixCheck trait
    #[test]
    fn test_prefix_check_ipv4() {
        let net_slash_24 = "192.168.1.0/24".parse::<Ipv4Net>().unwrap();
        let net_slash_32 = "192.168.1.1/32".parse::<Ipv4Net>().unwrap();
        let net_slash_8 = "10.0.0.0/8".parse::<Ipv4Net>().unwrap();

        // Check against min /24
        assert!(net_slash_24.meets_min_prefix(24));
        assert!(net_slash_32.meets_min_prefix(24)); // /32 >= /24
        assert!(!net_slash_8.meets_min_prefix(24)); // /8 < /24

        // Check against default constant (just logic check, value is 8)
        assert!(net_slash_24.meets_min_prefix(Ipv4Net::MIN_PREFIX_LEN_V4));
    }

    #[test]
    fn test_prefix_check_ipv6() {
        let net_slash_64 = "2001:db8::/64".parse::<Ipv6Net>().unwrap();
        let net_slash_128 = "::1/128".parse::<Ipv6Net>().unwrap();
        let net_slash_10 = "2000::/10".parse::<Ipv6Net>().unwrap();

        // Check against min /64
        assert!(net_slash_64.meets_min_prefix(64));
        assert!(net_slash_128.meets_min_prefix(64));
        assert!(!net_slash_10.meets_min_prefix(64));
    }

    #[test]
    #[should_panic(expected = "Minimum prefix for v4 <= 32")]
    fn test_prefix_check_ipv4_panic() {
        let net = "192.168.1.0/24".parse::<Ipv4Net>().unwrap();
        let _ = net.meets_min_prefix(33);
    }

    #[test]
    #[should_panic(expected = "Minimum prefix for v6 <= 128")]
    fn test_prefix_check_ipv6_panic() {
        let net = "::1/128".parse::<Ipv6Net>().unwrap();
        let _ = net.meets_min_prefix(129);
    }

    #[test]
    fn test_ipv6_prefix_new_valid() {
        assert!(Ipv6Prefix::new(0).is_some());
        assert!(Ipv6Prefix::new(64).is_some());
        assert!(Ipv6Prefix::new(128).is_some());
    }

    #[test]
    fn test_ipv6_prefix_new_invalid() {
        assert!(Ipv6Prefix::new(129).is_none());
        assert!(Ipv6Prefix::new(255).is_none());
    }

    #[test]
    fn test_ipv6_prefix_as_u8() {
        let prefix = Ipv6Prefix::new(64).unwrap();
        assert_eq!(prefix.as_u8(), 64);
    }

    #[test]
    fn test_ipv6_prefix_into_u8() {
        let prefix = Ipv6Prefix::new(64).unwrap();
        let value: u8 = prefix.into();
        assert_eq!(value, 64);
    }

    #[test]
    fn test_ipv6_prefix_try_from_bytes_valid() {
        assert!(Ipv6Prefix::try_from(b"0" as &[u8]).is_ok());
        assert!(Ipv6Prefix::try_from(b"64" as &[u8]).is_ok());
        assert!(Ipv6Prefix::try_from(b"128" as &[u8]).is_ok());
    }

    #[test]
    fn test_ipv6_prefix_try_from_bytes_invalid() {
        assert!(Ipv6Prefix::try_from(b"129" as &[u8]).is_err());
        assert!(Ipv6Prefix::try_from(b"255" as &[u8]).is_err());
        assert!(Ipv6Prefix::try_from(b"" as &[u8]).is_err());
        assert!(Ipv6Prefix::try_from(b"1234" as &[u8]).is_err()); // Too long
        assert!(Ipv6Prefix::try_from(b"12a" as &[u8]).is_err()); // Non-digit
        assert!(Ipv6Prefix::try_from(b"-1" as &[u8]).is_err()); // Negative
    }

    #[test]
    fn test_parse_raw_prefix_valid() {
        assert_eq!(parse_raw_prefix(b"0", 128), Some(0));
        assert_eq!(parse_raw_prefix(b"64", 128), Some(64));
        assert_eq!(parse_raw_prefix(b"128", 128), Some(128));
        assert_eq!(parse_raw_prefix(b"32", 32), Some(32));
    }

    #[test]
    fn test_parse_raw_prefix_invalid() {
        assert_eq!(parse_raw_prefix(b"", 128), None); // Empty
        assert_eq!(parse_raw_prefix(b"1234", 128), None); // Too long
        assert_eq!(parse_raw_prefix(b"129", 128), None); // Above max
        assert_eq!(parse_raw_prefix(b"33", 32), None); // Above max
        assert_eq!(parse_raw_prefix(b"12a", 128), None); // Non-digit
    }

    #[test]
    fn test_ipv6_prefix_roundtrip() {
        for i in 0..=128 {
            let prefix = Ipv6Prefix::new(i).unwrap();
            assert_eq!(prefix.as_u8(), i);

            let value: u8 = prefix.into();
            assert_eq!(value, i);
        }
    }
}
