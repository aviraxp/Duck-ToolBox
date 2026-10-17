//! The device-backed provisioning round trip.
//!
//! Unlike the offline workbench, this path never touches a seed: the challenge and the
//! certificate chain come from Google, the CSR is signed by the device's own KeyMint TA,
//! and only the private key stays on the host. Both sides of the exchange are traits so
//! the whole flow can be exercised without a device or a network.

use std::path::PathBuf;

use anyhow::Result;
use duck_core::BoxFuture;
use duck_core::{AppPaths, Context};
use duck_platform::net::{http_client, is_web_url};
use duck_rkp::{
    cose::{EcKeyPair, generate_ec_keypair},
    error::RkpError,
    http::{EekResponse, fetch_eek, submit_csr},
    profile::DEFAULT_SERVER_URL,
    verify::VerifyReport,
};
use reqwest::Client;
use serde::Serialize;

use crate::{
    artifacts::{self, ArtifactPaths, Artifacts, ChainSummary},
    error::DeviceRkpError,
    protocol::{self, MAX_CERT_CHAIN_LEN},
    status::{self, DeviceStatus, LIMITATIONS},
    worker,
};

/// Which TA command produces the CSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CsrVersion {
    /// KeyMint `CSR_V2`, command `0x3122`.
    #[default]
    V2,
    /// Keymaster `generateCsr`, command `0x311e`.
    V1,
}

impl CsrVersion {
    pub(crate) fn number(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    fn mode(self) -> &'static str {
        match self {
            Self::V1 => "device-ta-csr-v1",
            Self::V2 => "device-ta-oracle",
        }
    }
}

/// Everything the caller can still adjust without touching KeyMint.
#[derive(Debug, Clone, Default)]
pub(crate) struct Options {
    /// Override the build fingerprint sent to `fetchEekChain`.
    pub fingerprint: Option<String>,
    /// Also write `keybox.xml` here, instead of only inside the timestamped run directory.
    pub output: Option<PathBuf>,
    /// `V2` unless the device's trusted app only implements `generateCsr`.
    pub csr_version: CsrVersion,
}

/// Where the key pair that ends up in `keysToSign` comes from. Production uses the OS
/// RNG; a test substitutes a fixed pair so it can issue a certificate for it.
pub(crate) trait KeySource {
    fn generate(&self) -> Result<EcKeyPair>;
}

/// The production key source.
pub(crate) struct RandomKeys;

impl KeySource for RandomKeys {
    fn generate(&self) -> Result<EcKeyPair> {
        generate_ec_keypair()
    }
}

/// The vendor half of the round trip: one `CSR_V2` command in an isolated child process.
pub(crate) trait Exchange {
    fn csr(&self, request: &[u8]) -> Result<Vec<u8>>;
}

/// The capability report the run is gated on. Only tests replace it; the device answer
/// comes from `status::detect`.
pub(crate) trait Environment {
    fn capabilities(&self, ctx: &Context) -> DeviceStatus;
}

/// Everything the running device actually offers.
pub(crate) struct DeviceEnvironment;

impl Environment for DeviceEnvironment {
    fn capabilities(&self, ctx: &Context) -> DeviceStatus {
        status::detect(ctx)
    }
}

/// The Google half: the anti-replay challenge and the issued certificate chain. The
/// futures are boxed so the trait stays usable behind a reference.
pub(crate) trait Server: Sync {
    fn challenge<'a>(&'a self, fingerprint: &'a str) -> BoxFuture<'a, Result<EekResponse>>;
    fn certificates<'a>(
        &'a self,
        csr: &'a [u8],
        challenge: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>>;
}

/// The real vendor path. It runs inside a child process started from this binary.
pub(crate) struct Device<'a> {
    pub paths: &'a AppPaths,
}

impl Exchange for Device<'_> {
    fn csr(&self, request: &[u8]) -> Result<Vec<u8>> {
        worker::sign(self.paths, request)
    }
}

/// The real server path, through the shared HTTP client.
#[derive(Debug)]
pub(crate) struct Google {
    client: Client,
    server_url: String,
}

impl Google {
    pub(crate) fn new(server_url: Option<String>) -> Result<Self> {
        let server_url = server_url.unwrap_or_else(|| DEFAULT_SERVER_URL.to_owned());
        let server_url = server_url.trim().trim_end_matches('/').to_owned();
        if !is_web_url(&server_url) {
            return Err(RkpError::InvalidServerUrl(server_url).into());
        }
        Ok(Self {
            client: http_client()?,
            server_url,
        })
    }
}

impl Server for Google {
    fn challenge<'a>(&'a self, fingerprint: &'a str) -> BoxFuture<'a, Result<EekResponse>> {
        Box::pin(async move { fetch_eek(&self.client, fingerprint, &self.server_url).await })
    }

    fn certificates<'a>(
        &'a self,
        csr: &'a [u8],
        challenge: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>> {
        Box::pin(async move { submit_csr(&self.client, csr, challenge, &self.server_url).await })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ProvisionData {
    /// The run only happened because the caller acknowledged the limitations.
    pub acknowledged_limitations: bool,
    /// Stable identifiers of the limitations the user acknowledged.
    pub limitations: [&'static str; 2],
    /// How the CSR was produced, so a report can tell a device run from an offline one.
    pub mode: &'static str,
    /// `1` for Keymaster `generateCsr`, `2` for KeyMint `CSR_V2`.
    pub csr_version: u8,
    /// `false` for CSR v1: its device signature is encrypted to the server.
    pub local_signature_checked: bool,
    pub fingerprint: String,
    pub challenge_hex: String,
    pub csr_len: usize,
    pub local_verify: VerifyReport,
    pub chain: ChainSummary,
    pub device_id: String,
    pub keybox_xml: String,
    pub artifacts: ArtifactPaths,
    pub prerequisites: DeviceStatus,
}

/// Runs one complete provisioning round trip and writes every artifact.
pub(crate) async fn provision(
    ctx: &Context,
    acknowledged: bool,
    options: Options,
    key_source: &dyn KeySource,
    exchange: &dyn Exchange,
    server: &dyn Server,
    environment: &dyn Environment,
) -> Result<ProvisionData> {
    if !acknowledged {
        return Err(DeviceRkpError::AcknowledgementRequired.into());
    }

    let mut prerequisites = environment.capabilities(ctx);
    let explicit_fingerprint = options
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if explicit_fingerprint.is_some() {
        prerequisites
            .blockers
            .retain(|blocker| *blocker != "fingerprint_missing");
        prerequisites.prerequisites_met = prerequisites.blockers.is_empty();
    }
    if !prerequisites.prerequisites_met {
        return Err(DeviceRkpError::UnsupportedDevice(prerequisites.blockers.join(", ")).into());
    }

    let fingerprint = explicit_fingerprint
        .unwrap_or(prerequisites.fingerprint.trim())
        .to_owned();
    let key = key_source.generate()?;
    let eek = server.challenge(&fingerprint).await?;

    let (csr, local_verify) = match options.csr_version {
        CsrVersion::V2 => sign_v2(exchange, &eek, &key)?,
        CsrVersion::V1 => sign_v1(exchange, &eek, &key)?,
    };

    let chains = server.certificates(&csr, &eek.challenge).await?;
    let chain_der = single_chain(&chains)?;
    let mut artifacts = artifacts::write(
        &ctx.paths,
        artifacts::Inputs {
            secret_key: &key.secret_key,
            csr: &csr,
            cert_chain_der: &chain_der,
            manufacturer: &prerequisites.soc_manufacturer,
        },
    )?;
    if let Some(path) = options.output {
        artifacts::write_keybox(&path, &artifacts.keybox_xml)?;
        artifacts.paths.keybox_path = path.display().to_string();
    }

    Ok(report(
        options.csr_version,
        &fingerprint,
        &eek,
        &csr,
        local_verify,
        artifacts,
        prerequisites,
    ))
}

fn sign_v2(
    exchange: &dyn Exchange,
    eek: &EekResponse,
    key: &duck_rkp::cose::EcKeyPair,
) -> Result<(Vec<u8>, VerifyReport)> {
    let request = protocol::build_request(&eek.challenge, &key.cose_public)?;
    let signed = exchange.csr(&request)?;
    let csr = protocol::unwrap_csr(&signed)?;
    let local_verify = protocol::validate_csr(&csr, &eek.challenge, &key.cose_public)?;
    Ok((csr, local_verify))
}

fn sign_v1(
    exchange: &dyn Exchange,
    eek: &EekResponse,
    key: &duck_rkp::cose::EcKeyPair,
) -> Result<(Vec<u8>, VerifyReport)> {
    if eek.eek_chain.is_empty() {
        return Err(DeviceRkpError::InvalidCsr(
            "fetchEekChain did not include an EEK certificate chain".into(),
        )
        .into());
    }
    let mac_key = crate::protocol_v1::new_mac_key()?;
    let material = crate::protocol_v1::mac_material(&mac_key, &key.cose_public)?;
    let request = crate::protocol_v1::build_v1_request(&eek.challenge, &material, &eek.eek_chain)?;
    let payload = exchange.csr(&request)?;
    let parts = crate::protocol_v1::parse_v1_response(&payload)?;
    let local_verify = crate::protocol_v1::v1_report(&parts)?;
    let csr = crate::protocol_v1::assemble_v1_csr(
        &parts,
        &eek.challenge,
        &key.cose_public,
        &material.mac_tag,
    )?;
    Ok((csr, local_verify))
}

fn report(
    version: CsrVersion,
    fingerprint: &str,
    eek: &EekResponse,
    csr: &[u8],
    local_verify: VerifyReport,
    artifacts: Artifacts,
    prerequisites: DeviceStatus,
) -> ProvisionData {
    ProvisionData {
        acknowledged_limitations: true,
        limitations: LIMITATIONS,
        mode: version.mode(),
        csr_version: version.number(),
        local_signature_checked: version == CsrVersion::V2,
        fingerprint: fingerprint.to_owned(),
        challenge_hex: eek.challenge_hex.clone(),
        csr_len: csr.len(),
        local_verify,
        chain: ChainSummary::of(&artifacts.chain),
        device_id: artifacts.device_id.clone(),
        keybox_xml: artifacts.keybox_xml.clone(),
        artifacts: artifacts.paths.clone(),
        prerequisites,
    }
}

fn single_chain(chains: &[Vec<u8>]) -> Result<Vec<u8>> {
    let [chain] = chains else {
        return Err(RkpError::InvalidRkpResponse(format!(
            "expected one certificate chain for one requested key, got {}",
            chains.len()
        ))
        .into());
    };
    if chain.is_empty() || chain.len() > MAX_CERT_CHAIN_LEN {
        return Err(RkpError::InvalidRkpResponse(format!(
            "issued certificate chain must contain 1..{MAX_CERT_CHAIN_LEN} bytes"
        ))
        .into());
    }
    Ok(chain.to_vec())
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
