// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "zuul")]
#[command(about = "Templated nftables generator supporting remote blocklists", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub action: Action,

    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<String>,

    /// Path to template file
    #[arg(short, long)]
    pub template: Option<String>,

    /// Increase verbosity level (-v, -vv, -vvv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Number of worker threads
    #[arg(short = 'w', long, default_value_t = 8)]
    pub threads: usize,

    /// Timeout for requests in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    #[cfg(feature = "sandbox")]
    /// Enforce sandboxing
    #[arg(short = 's', long)]
    pub enforce_sandbox: bool,

    /// Perform a dry-run without making actual changes
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Start zuul and create firewall rules
    Start {
        #[arg(short = 'o', long = "stdout")]
        print_stdout: bool,
    },
    /// Stop zuul and remove firewall rules
    Stop,
    /// Restart zuul (stop then start)
    Restart,
    /// Update lists
    Refresh {
        #[arg(short = 'o', long = "stdout")]
        print_stdout: bool,
    },
    /// Display current configuration
    Config,
}
