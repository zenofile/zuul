use std::{fs, path::PathBuf, process::Command};

/// Helper to run a subcommand and compare its output against a golden file.
fn assert_golden(command: &str, extra_args: &[&str]) {
    let exe = env!("CARGO_BIN_EXE_rostschutz");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = root.join("tests/testdata/config-test.yaml");
    let expected_filename = format!("cli_expected_{}.txt", command);
    let expected_stdout_path = root.join("tests/testdata/stdout").join(&expected_filename);

    let output = Command::new(exe)
        .env("EPOCH_STABLE", "1766164828")
        .args(["-vv", "-n", "-c"])
        .arg(&config)
        .arg(command)
        .args(extra_args)
        .output()
        .expect("failed to spawn binary");

    assert!(
        output.status.success(),
        "Command '{}' failed.\nstatus: {:?}\nstderr:\n{}",
        command,
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let expected = fs::read(&expected_stdout_path).unwrap_or_else(|_| {
        panic!(
            "failed to read golden file: {}",
            expected_stdout_path.display()
        )
    });

    assert_eq!(
        output.stdout, expected,
        "stdout for '{}' did not match golden file '{}'",
        command, expected_filename
    );
}

#[test]
fn cli_config() {
    assert_golden("config", &[]);
}

#[test]
fn cli_start() {
    // "start" command with "-o" flag
    assert_golden("start", &["-o"]);
}

#[test]
fn cli_refresh() {
    assert_golden("refresh", &["-o"]);
}
