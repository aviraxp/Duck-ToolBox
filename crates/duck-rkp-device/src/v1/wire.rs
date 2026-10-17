use super::{Request, Response};
use crate::{error::DeviceRkpError, protocol::BUFFER_SIZE};
use anyhow::{Context, Result, bail};
use duck_rkp::cose::{RPC_CURVE_25519, RPC_CURVE_P256};
use std::io::{Cursor, Read};

pub(super) fn encode_request(request: &Request) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    field(&mut output, &request.challenge)?;
    field(&mut output, &request.maced_key)?;
    for curve in [RPC_CURVE_P256, RPC_CURVE_25519] {
        let chain = request.eek_chains.iter().find(|chain| chain.curve == curve);
        field(
            &mut output,
            chain.map_or(&[], |chain| chain.encoded.as_slice()),
        )?;
    }
    Ok(output)
}

fn field(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.len() > BUFFER_SIZE {
        bail!("V1 bridge field is too large");
    }
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn decode_response(bytes: &[u8]) -> Result<Response> {
    let mut input = Cursor::new(bytes);
    let status = number(&mut input)?;
    let result = match status {
        0 => Response {
            mac: read_field(&mut input)?,
            device_info: read_field(&mut input)?,
            protected_data: read_field(&mut input)?,
        },
        1 => {
            let code = number(&mut input)? as i32;
            let message = String::from_utf8(read_field(&mut input)?)?;
            ensure_end(&input)?;
            return Err(anyhow::Error::new(DeviceRkpError::Rejected(code))
                .context(format!("V1 AIDL: {message}")));
        }
        2 | 3 => {
            let message = String::from_utf8(read_field(&mut input)?)?;
            ensure_end(&input)?;
            let error = if status == 3 {
                DeviceRkpError::InvalidResponse(format!("V1 AIDL: {message}"))
            } else {
                DeviceRkpError::Transport(format!("V1 AIDL: {message}"))
            };
            return Err(error.into());
        }
        _ => bail!("unknown V1 bridge status {status}"),
    };
    ensure_end(&input)?;
    Ok(result)
}

fn ensure_end(input: &Cursor<&[u8]>) -> Result<()> {
    if input.position() != input.get_ref().len() as u64 {
        bail!("trailing V1 bridge reply data");
    }
    Ok(())
}

fn number(input: &mut Cursor<&[u8]>) -> Result<u32> {
    let mut number = [0; 4];
    input
        .read_exact(&mut number)
        .context("truncated V1 bridge header")?;
    Ok(u32::from_be_bytes(number))
}

fn read_field(input: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = number(input)? as usize;
    if len > BUFFER_SIZE {
        bail!("V1 bridge reply field is too large");
    }
    let mut bytes = vec![0; len];
    input
        .read_exact(&mut bytes)
        .context("truncated V1 bridge field")?;
    Ok(bytes)
}
