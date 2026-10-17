use super::{APP_PROCESS, Request, Response, wire};
use crate::{error::DeviceRkpError, process, protocol::BUFFER_SIZE};
use anyhow::{Context, Result};
use duck_core::AppPaths;
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const BRIDGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rkp-v1.jar"));
#[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
const BRIDGE: &[u8] = &[];

pub(crate) fn sign(paths: &AppPaths, apk: &Path, request: &Request) -> Result<Response> {
    if BRIDGE.is_empty() {
        return Err(DeviceRkpError::UnsupportedDevice("V1 requires Android arm64".into()).into());
    }
    run(paths, apk, request).map_err(|error| {
        if error.chain().any(|cause| cause.is::<DeviceRkpError>()) {
            error
        } else {
            DeviceRkpError::Transport(format!("V1 bridge failed: {error:#}")).into()
        }
    })
}

fn run(paths: &AppPaths, apk: &Path, request: &Request) -> Result<Response> {
    let input = wire::encode_request(request)?;
    fs::create_dir_all(&paths.tmp_dir).context("create V1 temporary directory")?;
    let exchange = tempfile::Builder::new()
        .prefix("rkp-v1-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&paths.tmp_dir)?;
    let jar = exchange.path().join("bridge.jar");
    fs::write(&jar, BRIDGE)?;
    // ART on newer releases requires dynamically loaded code to be read-only.
    fs::set_permissions(&jar, fs::Permissions::from_mode(0o400))?;
    fs::write(exchange.path().join("request.bin"), input)?;
    let mut command = Command::new(APP_PROCESS);
    command
        .env("CLASSPATH", format!("{}:{}", jar.display(), apk.display()))
        .args(["/system/bin", "duck.rkp.RkpV1Bridge"])
        .arg(exchange.path());
    let status = process::run(&mut command, Duration::from_secs(30))?;
    if !status.success() {
        return Err(DeviceRkpError::Transport(format!("V1 bridge exited with {status}")).into());
    }
    let bytes =
        process::read_exchange_file(&exchange.path().join("reply.bin"), BUFFER_SIZE * 3 + 16)?;
    wire::decode_response(&bytes).map_err(|error| {
        if error.chain().any(|cause| cause.is::<DeviceRkpError>()) {
            error
        } else {
            DeviceRkpError::InvalidResponse(format!("V1 bridge: {error:#}")).into()
        }
    })
}
