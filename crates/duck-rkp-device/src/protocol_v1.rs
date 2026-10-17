//! CSR v1, the `generateCsr` command on older Qualcomm Keymaster firmware.
//!
//! Command `0x311e` is `KEYMINT_GENERATE_CSR`. The request map is
//! `{4: challenge, 55: testMode, 56: macKey, 57: macTag, 58: eekChain}`.
//! The response map is `{59: deviceInfo, 60: protectedData}`. Both byte strings are
//! already encoded CBOR. The server body is the legacy four-element certificate request:
//! DeviceInfo, the challenge, ProtectedData, and a `COSE_Mac0` over the key to sign.
//!
//! ProtectedData is encrypted to Google's EEK, so the device signature inside it cannot
//! be checked here.

use std::io::Cursor;

use anyhow::{Context, Result, bail};
use ciborium::value::Value;
use duck_rkp::{
    cbor::{as_array, as_bytes, as_i128, as_map, as_text, encode, int, map_get, map_get_text},
    cose::{cose_mac0, key_mac_tag},
    verify::VerifyReport,
};

use crate::{error::DeviceRkpError, protocol::MAX_REQUEST_SIZE};

pub(crate) const CSR_V1_COMMAND: u32 = 0x311e;
const TEST_MODE: i128 = 0;
const CHALLENGE: i128 = 4;
const MAC_KEY: i128 = 56;
const MAC_TAG: i128 = 57;
const EEK_CHAIN: i128 = 58;
const DEVICE_INFO: i128 = 59;
const PROTECTED_DATA: i128 = 60;
const MAC_LEN: usize = 32;

pub(crate) struct V1Material {
    pub mac_key: [u8; MAC_LEN],
    pub mac_tag: [u8; MAC_LEN],
}

pub(crate) struct V1Parts {
    pub device_info: Vec<u8>,
    pub protected_data: Vec<u8>,
}

pub(crate) fn new_mac_key() -> Result<[u8; MAC_LEN]> {
    let mut key = [0_u8; MAC_LEN];
    getrandom::fill(&mut key).context("generate the CSR v1 MAC key")?;
    Ok(key)
}

pub(crate) fn mac_material(mac_key: &[u8; MAC_LEN], public_key: &Value) -> Result<V1Material> {
    let mac_tag = key_mac_tag(mac_key, std::slice::from_ref(public_key))?;
    Ok(V1Material {
        mac_key: *mac_key,
        mac_tag,
    })
}

/// Builds the TA request: little-endian command id, then the CBOR map.
pub(crate) fn build_v1_request(
    challenge: &[u8],
    material: &V1Material,
    eek_chain: &[u8],
) -> Result<Vec<u8>> {
    let payload = encode(&Value::Map(vec![
        (int(CHALLENGE), Value::Bytes(challenge.to_vec())),
        (int(55), int(TEST_MODE)),
        (int(MAC_KEY), Value::Bytes(material.mac_key.to_vec())),
        (int(MAC_TAG), Value::Bytes(material.mac_tag.to_vec())),
        (int(EEK_CHAIN), Value::Bytes(eek_chain.to_vec())),
    ]))?;
    validate_v1_request(&payload)?;
    let mut request = CSR_V1_COMMAND.to_le_bytes().to_vec();
    request.extend_from_slice(&payload);
    Ok(request)
}

pub(crate) fn validate_v1_request(payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_REQUEST_SIZE - 4 {
        bail!("CSR request is too large");
    }
    let value = decode_exact(payload)?;
    let entries = as_map(&value, "CSR v1 request")?;
    if entries.len() != 5 {
        bail!("CSR v1 request must contain testMode, challenge, MAC key, MAC tag and EEK chain");
    }
    if as_i128(required(entries, 55, "testMode")?, "testMode")? != TEST_MODE {
        bail!("CSR v1 testMode must be 0");
    }
    let challenge = as_bytes(required(entries, CHALLENGE, "challenge")?, "challenge")?;
    if challenge.is_empty() || challenge.len() > 64 {
        bail!("server challenge must be 1..64 bytes");
    }
    require_len(entries, MAC_KEY, "MAC key", MAC_LEN)?;
    require_len(entries, MAC_TAG, "MAC tag", MAC_LEN)?;
    let chain = as_bytes(required(entries, EEK_CHAIN, "EEK chain")?, "EEK chain")?;
    if chain.is_empty() {
        bail!("EEK certificate chain is empty");
    }
    Ok(())
}

pub(crate) fn parse_v1_response(payload: &[u8]) -> Result<V1Parts> {
    let value = decode_exact(payload)
        .map_err(|error| DeviceRkpError::InvalidResponse(format!("CSR v1 response: {error:#}")))?;
    let entries = as_map(&value, "CSR v1 response").map_err(invalid_response)?;
    if entries.len() != 2 {
        return Err(invalid_response(anyhow::anyhow!(
            "CSR v1 response must contain device info and protected data"
        )));
    }
    let device_info = as_bytes(
        required(entries, DEVICE_INFO, "deviceInfo").map_err(invalid_response)?,
        "deviceInfo",
    )
    .map_err(invalid_response)?
    .to_vec();
    let protected_data = as_bytes(
        required(entries, PROTECTED_DATA, "protectedData").map_err(invalid_response)?,
        "protectedData",
    )
    .map_err(invalid_response)?
    .to_vec();
    check_parts(&device_info, &protected_data)?;
    Ok(V1Parts {
        device_info,
        protected_data,
    })
}

pub(crate) fn assemble_v1_csr(
    parts: &V1Parts,
    challenge: &[u8],
    public_key: &Value,
    mac_tag: &[u8; MAC_LEN],
) -> Result<Vec<u8>> {
    check_parts(&parts.device_info, &parts.protected_data)?;
    let mac = cose_mac0(std::slice::from_ref(public_key), mac_tag)?;
    let mut csr = vec![0x84];
    csr.extend_from_slice(&parts.device_info);
    csr.extend_from_slice(&encode(&Value::Bytes(challenge.to_vec()))?);
    csr.extend_from_slice(&parts.protected_data);
    csr.extend_from_slice(&mac);
    decode_exact(&csr).context("assemble CSR v1 certificate request")?;
    Ok(csr)
}

/// Structural report only. `signature_valid` stays false: the signature is inside
/// ProtectedData, which only the RKP server can decrypt.
pub(crate) fn v1_report(parts: &V1Parts) -> Result<VerifyReport> {
    check_parts(&parts.device_info, &parts.protected_data)?;
    Ok(VerifyReport {
        version: 1,
        dice_entries: 0,
        uds_pub_hex: String::new(),
        signature_valid: false,
        csr_version: 1,
        cert_type: "csr-v1".to_owned(),
        brand: brand_of(&parts.device_info),
        keys_to_sign: 1,
    })
}

fn check_parts(device_info: &[u8], protected_data: &[u8]) -> Result<()> {
    let info = decode_exact(device_info).map_err(invalid_csr)?;
    as_map(&info, "DeviceInfo").map_err(invalid_csr)?;
    let protected = decode_exact(protected_data).map_err(invalid_csr)?;
    let items = as_array(&protected, "ProtectedData").map_err(invalid_csr)?;
    if items.len() != 4 {
        return Err(invalid_csr(anyhow::anyhow!(
            "ProtectedData must be a COSE_Encrypt array of 4"
        )));
    }
    Ok(())
}

fn brand_of(device_info: &[u8]) -> Option<String> {
    let value = decode_exact(device_info).ok()?;
    let entries = as_map(&value, "DeviceInfo").ok()?;
    let brand = map_get_text(entries, "brand")?;
    as_text(brand, "brand").ok().map(str::to_owned)
}

fn require_len(entries: &[(Value, Value)], key: i128, label: &str, len: usize) -> Result<()> {
    let bytes = as_bytes(required(entries, key, label)?, label)?;
    if bytes.len() != len {
        bail!("{label} must be {len} bytes");
    }
    Ok(())
}

fn required<'a>(entries: &'a [(Value, Value)], key: i128, label: &str) -> Result<&'a Value> {
    map_get(entries, key).ok_or_else(|| anyhow::anyhow!("{label} is missing label {key}"))
}

fn decode_exact(bytes: &[u8]) -> Result<Value> {
    let mut reader = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut reader).context("decode CBOR")?;
    if reader.position() != bytes.len() as u64 {
        bail!("CBOR contains trailing data");
    }
    Ok(value)
}

fn invalid_response(error: anyhow::Error) -> anyhow::Error {
    DeviceRkpError::InvalidResponse(format!("{error:#}")).into()
}

fn invalid_csr(error: anyhow::Error) -> anyhow::Error {
    DeviceRkpError::InvalidCsr(format!("{error:#}")).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use duck_rkp::cbor::{as_bytes, as_i128, bytes, decode, map_get};

    fn public_key() -> Value {
        Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), bytes(vec![0x11; 32])),
            (int(-3), bytes(vec![0x22; 32])),
        ])
    }

    fn parts() -> V1Parts {
        let device_info = encode(&Value::Map(vec![(
            Value::Text("brand".into()),
            Value::Text("qualcomm".into()),
        )]))
        .unwrap();
        let protected_data = encode(&Value::Array(vec![
            bytes(vec![1]),
            Value::Map(vec![]),
            bytes(vec![2]),
            Value::Array(vec![]),
        ]))
        .unwrap();
        V1Parts {
            device_info,
            protected_data,
        }
    }

    #[test]
    fn request_uses_the_keymaster_command_and_fixed_widths() {
        let key = public_key();
        let mac_key = [0xAB; 32];
        let material = mac_material(&mac_key, &key).unwrap();
        let request = build_v1_request(&[0x10; 16], &material, &[0x80]).unwrap();

        assert_eq!(request[..4], CSR_V1_COMMAND.to_le_bytes());
        let Value::Map(entries) = decode(&request[4..]).unwrap() else {
            panic!("payload must be a map");
        };
        assert_eq!(
            as_i128(map_get(&entries, 55).unwrap(), "testMode").unwrap(),
            0
        );
        assert_eq!(
            as_bytes(map_get(&entries, 56).unwrap(), "mac").unwrap(),
            &mac_key
        );
        assert_eq!(
            as_bytes(map_get(&entries, 57).unwrap(), "tag")
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn round_trip_builds_a_four_element_server_request() {
        let key = public_key();
        let material = mac_material(&[7; 32], &key).unwrap();
        let parts = parts();
        let payload = encode(&Value::Map(vec![
            (int(DEVICE_INFO), bytes(parts.device_info.clone())),
            (int(PROTECTED_DATA), bytes(parts.protected_data.clone())),
        ]))
        .unwrap();
        let parsed = parse_v1_response(&payload).unwrap();
        let csr = assemble_v1_csr(&parsed, &[0x10; 16], &key, &material.mac_tag).unwrap();
        let report = v1_report(&parsed).unwrap();

        assert_eq!(csr[0], 0x84);
        assert!(!report.signature_valid);
        assert_eq!(report.csr_version, 1);
        assert_eq!(report.brand.as_deref(), Some("qualcomm"));
        let Value::Array(items) = decode(&csr).unwrap() else {
            panic!("server CSR must be an array");
        };
        assert_eq!(items.len(), 4);
        let Value::Array(mac) = &items[3] else {
            panic!("fourth element must be COSE_Mac0");
        };
        let Value::Bytes(payload) = &mac[2] else {
            panic!("MAC payload must be bytes");
        };
        let Value::Array(keys) = decode(payload).unwrap() else {
            panic!("MAC payload must be a key array");
        };
        assert_eq!(keys[0], key);
    }
}
