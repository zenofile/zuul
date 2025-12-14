// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::{collections::HashMap, fs, io::Write, sync::Arc};

use anyhow::{Context, Result};

use crate::{
    config::{Config, IpVersion},
    sets::{NetSet, SetInventory, SetType},
};

#[derive(Debug, Clone)]
pub struct LazyIpSet<T> {
    pub data: Arc<NetSet<T>>,
    pub set_type: SetType,
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

    use crate::{render::LazyIpSet, sets::SetType};

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

#[derive(Debug)]
pub struct RenderContext<'a> {
    pub cfg: &'a Config,
    pub sets: &'a SetInventory,
}

impl<'a> RenderContext<'a> {
    const fn new(cfg: &'a Config, sets: &'a SetInventory) -> Self {
        Self { cfg, sets }
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

        for ip_version in cfg.net.get_active() {
            for base_name in targets {
                let full_name = format!("{}_{}", base_name, ip_version);

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

pub fn render_template(
    context: &crate::AppContext,
    sets: &SetInventory,
    writer: &mut dyn Write,
    block_name: &str,
    epoch: u64,
) -> Result<()> {
    let template_content =
        fs::read_to_string(&context.template).context("Failed to read template file")?;

    let mut jinja = minijinja::Environment::new();
    jinja.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
    jinja.set_trim_blocks(true);
    jinja.set_lstrip_blocks(true);
    jinja.add_template("zuul", &template_content)?;
    let template = jinja.get_template("zuul")?;

    let processor = RenderContext::new(&context.config, sets);
    let mut all_sets = HashMap::new();

    let mut collect = |_, name: &str, val: &minijinja::Value| {
        all_sets.insert(name.to_owned(), val.clone());
        Ok(())
    };

    processor.for_each_set(SetType::Static, &mut collect)?;
    processor.for_each_set(SetType::Dynamic, &mut collect)?;

    let cfg = &context.config;
    use minijinja::context;

    // // Build map of set_name -> set_name_ipv
    // let mut set_mappings = HashMap::new();
    // for ver in [IpVersion::V4, IpVersion::V6] {
    //     // Static sets don't change
    //     let wl = format!("{}_{}", cfg.set_names.whitelist, ver);
    //     set_mappings.insert(wl.clone(), wl);
    //     let bl = format!("{}_{}", cfg.set_names.blacklist, ver);
    //     set_mappings.insert(bl.clone(), bl);
    //
    //     let al = format!("{}_{}", cfg.set_names.abuselist, ver);
    //     set_mappings.insert(al.clone(), al);
    //
    //     let cl = format!("{}_{}", cfg.set_names.country, ver);
    //     set_mappings.insert(cl.clone(), cl);
    // }

    let ctx = context! {
        iifname => &cfg.iifname,
        default_policy => &cfg.default_policy,
        block_policy => &cfg.block_policy,
        logging => &cfg.logging,
        set_names => &cfg.set_names,
        sets => all_sets,
        epoch => epoch,
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

#[cfg(test)]
mod teste {
    use super::*;

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
