// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

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
mod loader;
mod nft;
mod render;
mod sets;
mod threadpool;

#[cfg(feature = "sandbox")]
mod sandbox;

use std::{
    env,
    io::{IsTerminal, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::prelude::*;

use crate::{
    cli::{Action, Cli},
    config::{Config, resolve_fragment},
    loader::collect_ip_sets,
    render::render_template,
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

use std::time::{SystemTime, UNIX_EPOCH};

#[inline]
#[must_use]
fn get_epoch_revision() -> u64 {
    env::var("EPOCH_STABLE").map_or_else(
        |_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        },
        |val| val.parse::<u64>().expect("Valid unix timestamp"),
    )
}

fn start(context: &AppContext) -> Result<()> {
    info!("Starting rostschutz");

    let epoch = get_epoch_revision();
    let sets = collect_ip_sets(context);

    info!("Generating dynamic sets with epoch suffix {}", epoch);

    let generator = |writer: &mut dyn Write| -> Result<()> {
        render_template(context, &sets, writer, "full_config", epoch)
    };

    if context.print_stdout {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        generator(&mut handle)?;
    } else {
        nft::run_nft_stream(context.dry_run, generator)?;
    }
    Ok(())
}

fn stop() -> Result<()> {
    info!("Stopping rostschutz");
    nft::run_nft_cli(&["delete", "table", "netdev", "blackhole"], false)?;
    info!("Successfully deleted nftables table 'netdev blackhole'");

    Ok(())
}

fn refresh(context: &AppContext) -> Result<()> {
    info!("Reloading abuselist and country lists");
    let epoch = get_epoch_revision();
    let sets = collect_ip_sets(context);

    info!("Applying atomic update with epoch suffix {}", epoch);

    // Combine everything into one single transaction
    let atomic_update = |writer: &mut dyn Write| -> Result<()> {
        // TABLE BEGIN
        writeln!(writer, "flush chain netdev blackhole validation")?;
        writeln!(writer, "table netdev blackhole {{")?;
        render_template(context, &sets, writer, "sets_dynamic", epoch)?;
        render_template(context, &sets, writer, "chain_validation", epoch)?;
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
        nft::run_nft_stream(context.dry_run, atomic_update)?;
    }

    // Step 4: Clean up old sets
    if !context.print_stdout {
        info!("Cleaning up old sets");
        nft::cleanup_old_sets(context, epoch)?;
    }

    let (total_v4, total_v6) = sets.log_totals();
    info!(
        "Reloaded total entries IPv4: {} IPv6: {}",
        total_v4, total_v6
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Logging
    {
        let level_filter = if cli.quiet {
            LevelFilter::OFF
        } else {
            match cli.verbose {
                0 => LevelFilter::WARN,
                1 => LevelFilter::INFO,
                2 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            }
        };

        if env::var("JOURNAL_STREAM").is_ok() {
            let journald_layer = tracing_journald::layer().expect("Failed to connect to journald");

            // journald
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(level_filter.into()),
                )
                .with(journald_layer)
                .init();
        } else {
            // tty
            let use_ansi = std::io::stdout().is_terminal();
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(level_filter.into()),
                )
                .with_writer(std::io::stderr)
                .with_ansi(use_ansi)
                .init();
        }
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
        Ok(status) => warn!("Landlock sandbox is only: {}", status),
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
