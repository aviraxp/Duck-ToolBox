use std::path::PathBuf;

use clap::Subcommand;
use duck_core::{BoxFuture, ClapFeature, CommandResult, Context, FeatureInfo, IntoCommandResult};

use crate::{error::code_of, service, status, worker};

pub static FEATURE: ClapFeature<Command> = ClapFeature::new(
    FeatureInfo {
        id: "rkp-device",
        summary: "Device-backed RKP issuance on compatible Qualcomm KeyMint firmware",
        contract: 3,
    },
    dispatch,
);

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check prerequisites without sending commands to KeyMint or contacting a server.
    Status,
    /// Issue one RKP ECDSA keybox using this device's KeyMint TA (compatible firmware only).
    Provision {
        /// Acknowledge that only some devices work and that only RKP certificates are issued.
        #[arg(long)]
        acknowledge_limitations: bool,
        /// Build fingerprint sent to `fetchEekChain` instead of the device's own.
        #[arg(long)]
        fingerprint: Option<String>,
        /// RKP server base URL (for example a local proxy during development).
        #[arg(long)]
        server_url: Option<String>,
        /// Also write `keybox.xml` here. The run directory keeps the private key and the CSR.
        #[arg(long)]
        output: Option<String>,
        /// `2` is KeyMint CSR_V2 (command `0x3122`). `1` is Keymaster generateCsr (`0x311e`).
        #[arg(long, default_value_t = 2, value_parser = parse_csr_version)]
        csr_version: u8,
    },
    /// Private subprocess boundary for vendor code, with its output isolated from JSON stdout.
    #[command(hide = true)]
    TaCsr {
        #[arg(long)]
        exchange: PathBuf,
    },
}

fn parse_csr_version(value: &str) -> Result<u8, String> {
    match value {
        "1" | "2" => Ok(value.parse().expect("1 and 2 parse as u8")),
        _ => Err("CSR version must be 1 or 2".to_owned()),
    }
}

fn csr_version_of(value: u8) -> service::CsrVersion {
    match value {
        1 => service::CsrVersion::V1,
        _ => service::CsrVersion::V2,
    }
}

fn dispatch<'a>(command: Command, ctx: &'a Context) -> BoxFuture<'a, CommandResult> {
    Box::pin(async move {
        match command {
            Command::Status => {
                let status: anyhow::Result<status::DeviceStatus> = Ok(status::detect(ctx));
                status.into_command("rkp-device.status", code_of)
            }
            Command::Provision {
                acknowledge_limitations,
                fingerprint,
                server_url,
                output,
                csr_version,
            } => {
                let options = service::Options {
                    fingerprint,
                    output: output.map(|path| ctx.paths.resolve_in_root(&path)),
                    csr_version: csr_version_of(csr_version),
                };
                let server = service::Google::new(server_url);
                match server {
                    Ok(server) => service::provision(
                        ctx,
                        acknowledge_limitations,
                        options,
                        &service::RandomKeys,
                        &service::Device { paths: &ctx.paths },
                        &server,
                        &service::DeviceEnvironment,
                    )
                    .await
                    .into_command("rkp-device.provision", code_of),
                    Err(error) => {
                        let failed: anyhow::Result<service::ProvisionData> = Err(error);
                        failed.into_command("rkp-device.provision", code_of)
                    }
                }
            }
            Command::TaCsr { exchange } => {
                worker::execute(&exchange).into_command("rkp-device.ta-csr", code_of)
            }
        }
    })
}
