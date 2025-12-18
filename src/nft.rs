// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::process::{Command, Output};

use anyhow::{Context, Result};
use tracing::{debug, error, info};

use crate::AppContext;

// Spawns `nft -f -` and executes the provided callback to write rules to its stdin.
/// Handles broken pipes gracefully (ignoring them if caused by early nft exit)
pub fn run_nft_stream<F>(dry_run: bool, write_op: F) -> Result<()>
where
    F: FnOnce(&mut dyn std::io::Write) -> Result<()>,
{
    if dry_run {
        debug!("Dry-run, no-op command: nft -f -");
        let mut sink = std::io::sink();
        write_op(&mut sink)?;
        return Ok(());
    }

    info!("Executing command: nft -f -");
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
        error!("Command failed: {}", stderr);
        return Err(anyhow::anyhow!("Execution error: {stderr}"));
    }

    Ok(())
}

pub fn run_nft_cli(args: &[&str], dry_run: bool) -> Result<Output> {
    if dry_run {
        debug!("Dry-run, no-op command: nft {}", args.join(" "));
        let mock_status = std::os::unix::process::ExitStatusExt::from_raw(0);
        return Ok(Output {
            status: mock_status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
    }

    info!("Executing command: nft {}", args.join(" "));
    let output = Command::new("nft")
        .args(args)
        .output()
        .context("Failed to execute command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Command failed: {}", stderr);
        return Err(anyhow::anyhow!("execution error: {stderr}"));
    }
    Ok(output)
}

pub fn cleanup_old_sets(context: &AppContext, active_epoch: u64) -> Result<()> {
    debug!("Checking for old sets to clean up");
    let output = run_nft_cli(
        &["--terse", "list", "sets", "table", "netdev", "blackhole"],
        context.dry_run,
    )?;

    if context.dry_run {
        debug!("Dry-run, not cleaning up anything");
        return Ok(());
    }

    let cfg = &context.config;
    let dynamic_bases = [&cfg.set_names.abuselist, &cfg.set_names.country];
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"set\s+([a-zA-Z0-9_]+)\s+\{").expect("Invalid regex");

    for cap in re.captures_iter(&stdout) {
        let name = &cap[1];

        // Check if this set belongs to one of our dynamic categories
        let is_dynamic = dynamic_bases
            .iter()
            .any(|base| name.starts_with(&format!("{}_", base)));

        if is_dynamic && !name.ends_with(&format!("_{}", active_epoch)) {
            info!("Found dynamic set {}, deleting", name);
            // Ignore errors - set might be in use or already deleted
            let _ = run_nft_cli(
                &["delete", "set", "netdev", "blackhole", name],
                context.dry_run,
            );
        }
    }
    Ok(())
}
