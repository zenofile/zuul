// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::sync::Arc;

use crate::config::StaticCow;

/// Immutable String (wrapper around Arc<str>)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IStr(Arc<str>);

impl IStr {
    #[allow(unused)]
    pub fn new(s: impl Into<Arc<str>>) -> Self {
        Self(s.into())
    }
}

impl Default for IStr {
    fn default() -> Self {
        Self(Arc::from(""))
    }
}

impl std::fmt::Display for IStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Forwards to impl Display for str
        std::fmt::Display::fmt(&self.0, f)
    }
}

// Allows IStr to be used like &str
impl std::ops::Deref for IStr {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // &self.0 is &Arc<str>.
        // We need to return &str.
        // Use explicit dereference or as_ref() if implicit coercion fails.
        &self.0
    }
}

impl std::borrow::Borrow<str> for IStr {
    fn borrow(&self) -> &str {
        &self.0
    }
}

// Easy conversion from string literals and owned strings
impl From<&str> for IStr {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

impl From<String> for IStr {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<StaticCow> for IStr {
    fn from(s: StaticCow) -> Self {
        Self(Arc::from(s))
    }
}

mod serde_impls {
    // Import parents to access IStr and other types
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::IStr;

    impl Serialize for IStr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.0)
        }
    }

    impl<'de> Deserialize<'de> for IStr {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(Self::from(String::deserialize(deserializer)?))
        }
    }
}
