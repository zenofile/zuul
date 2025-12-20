use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

#[test]
fn cli_start_verify_nft_syntax() {
    let exe = env!("CARGO_BIN_EXE_zuul");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = root.join("tests/testdata/config-test.yaml");

    let zuul_output = Command::new(exe)
        .env("EPOCH_STABLE", "1766164828")
        .args(["-q", "-n", "-c"])
        .arg(&config)
        .arg("start")
        .arg("-o")
        .output()
        .expect("failed to spawn binary");

    assert!(zuul_output.status.success(), "Generation failed");

    let mut nft_cmd = Command::new("nft");
    nft_cmd
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match nft_cmd.spawn() {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(&zuul_output.stdout)
                    .expect("write to nft failed");
            }
            let output = child.wait_with_output().expect("wait on nft failed");

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);

                if stderr.contains("Operation not permitted")
                    || stderr.contains("Permission denied")
                    || stderr.contains("cache initialization failed")
                {
                    println!(
                        "SKIPPING: 'nft' requires privileges (CAP_NET_ADMIN). Syntax check \
                         skipped."
                    );
                    println!("stderr output: {}", stderr.trim());
                    return;
                }

                panic!("nft syntax check failed:\n{}", stderr);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("SKIPPING: 'nft' binary not found.");
        }
        Err(e) => panic!("failed to spawn nft: {}", e),
    }
}
