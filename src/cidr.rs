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

    #[must_use]
    pub fn to_netmask(self) -> std::net::Ipv4Addr {
        let shift = 32 - self.0;
        let mask = (!0u32).checked_shl(shift.into()).unwrap_or(0);
        std::net::Ipv4Addr::from(mask)
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
    const MIN_PREFIX_LEN_V4: u8 = 8;
    const MIN_PREFIX_LEN_V6: u8 = 16;

    fn meets_min_prefix(&self, min: u8) -> bool;
}

impl PrefixCheck for ipnet::Ipv4Net {
    #[inline]
    fn meets_min_prefix(&self, min: u8) -> bool {
        self.prefix_len() >= min
    }
}

impl PrefixCheck for ipnet::Ipv6Net {
    #[inline]
    fn meets_min_prefix(&self, min: u8) -> bool {
        self.prefix_len() >= min
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for Ipv6Prefix::new()
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

    // Tests for Ipv6Prefix::as_u8()
    #[test]
    fn test_ipv6_prefix_as_u8() {
        let prefix = Ipv6Prefix::new(64).unwrap();
        assert_eq!(prefix.as_u8(), 64);
    }

    // Tests for Ipv6Prefix::to_netmask()
    #[test]
    fn test_ipv6_prefix_to_netmask() {
        let prefix = Ipv6Prefix::new(24).unwrap();
        assert_eq!(
            prefix.to_netmask(),
            std::net::Ipv4Addr::new(255, 255, 255, 0)
        );

        let prefix = Ipv6Prefix::new(32).unwrap();
        assert_eq!(prefix.to_netmask(), std::net::Ipv4Addr::BROADCAST);

        let prefix = Ipv6Prefix::new(0).unwrap();
        assert_eq!(prefix.to_netmask(), std::net::Ipv4Addr::UNSPECIFIED);

        let prefix = Ipv6Prefix::new(16).unwrap();
        assert_eq!(prefix.to_netmask(), std::net::Ipv4Addr::new(255, 255, 0, 0));
    }

    // Tests for From<Ipv6Prefix> for u8
    #[test]
    fn test_ipv6_prefix_into_u8() {
        let prefix = Ipv6Prefix::new(64).unwrap();
        let value: u8 = prefix.into();
        assert_eq!(value, 64);
    }

    // Tests for TryFrom<&[u8]> for Ipv{4,6}Prefix
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

    // Tests for parse_raw_prefix helper
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
}
