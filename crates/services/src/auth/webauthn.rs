use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier};
use p256::{
    ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey},
    EncodedPoint,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const COSE_KEY_LABEL_KTY: i8 = 1;
pub const COSE_KEY_LABEL_ALG: i8 = 3;
pub const COSE_KEY_LABEL_CRV: i8 = -1;
pub const COSE_KEY_LABEL_X: i8 = -2;
pub const COSE_KEY_LABEL_Y: i8 = -3;

pub const COSE_KTY_EC2: i8 = 2;
pub const COSE_KTY_OKP: i8 = 1;

pub const COSE_CRV_P256: i8 = 1;
pub const COSE_CRV_ED25519: i8 = 6;

pub const COSE_ALG_ES256: i8 = -7;
pub const COSE_ALG_EDDSA: i8 = -8;

#[derive(Debug, Clone)]
pub enum WebAuthnAlgorithm {
    Es256,
    EdDsa,
}

impl WebAuthnAlgorithm {
    pub fn label(&self) -> &'static str {
        match self {
            WebAuthnAlgorithm::Es256 => "p256",
            WebAuthnAlgorithm::EdDsa => "ed25519",
        }
    }

    pub fn from_cose_alg(alg: i8) -> anyhow::Result<Self> {
        match alg {
            COSE_ALG_ES256 => Ok(Self::Es256),
            COSE_ALG_EDDSA => Ok(Self::EdDsa),
            _ => Err(anyhow::anyhow!("Unsupported COSE algorithm {alg}")),
        }
    }
}

fn value_to_i8(value: &Value, field: &str) -> anyhow::Result<i8> {
    if let Value::Integer(i) = value {
        let raw: i128 = (*i).into();
        i8::try_from(raw).map_err(|_| anyhow::anyhow!("{field} value out of range"))
    } else {
        Err(anyhow::anyhow!("{field} must be an integer"))
    }
}

fn option_value_to_i8(opt: Option<&Value>, field: &str) -> anyhow::Result<Option<i8>> {
    match opt {
        Some(value) => Ok(Some(value_to_i8(value, field)?)),
        None => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPublicKey {
    pub algorithm: WebAuthnAlgorithm,
    pub bytes: Vec<u8>,
}

pub fn generate_challenge_bytes(len: usize) -> Vec<u8> {
    let mut challenge = vec![0u8; len];
    rand::rng().fill_bytes(&mut challenge);
    challenge
}

pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn base64url_decode(data: &str) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| anyhow::anyhow!("Invalid base64url data: {e}"))
}

pub fn parse_cose_public_key(cbor_bytes: &[u8]) -> anyhow::Result<ParsedPublicKey> {
    let value: Value = ciborium::de::from_reader(cbor_bytes)?;
    let map = match value {
        Value::Map(map) => map,
        _ => return Err(anyhow::anyhow!("COSE key is not a map")),
    };

    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;

    for (key, val) in map {
        if let Value::Integer(label) = key {
            let label_value = i8::try_from(i128::from(label)).unwrap_or_default();
            match label_value {
                COSE_KEY_LABEL_KTY => kty = Some(val),
                COSE_KEY_LABEL_ALG => alg = Some(val),
                COSE_KEY_LABEL_CRV => crv = Some(val),
                COSE_KEY_LABEL_X => x = Some(val),
                COSE_KEY_LABEL_Y => y = Some(val),
                _ => {}
            }
        }
    }

    let alg_value = alg
        .as_ref()
        .map(|value| value_to_i8(value, "alg"))
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("Missing alg in COSE key"))?;

    let algorithm = WebAuthnAlgorithm::from_cose_alg(alg_value)?;

    match algorithm {
        WebAuthnAlgorithm::Es256 => {
            if option_value_to_i8(kty.as_ref(), "kty")? != Some(COSE_KTY_EC2) {
                return Err(anyhow::anyhow!("Invalid kty for ES256"));
            }
            if option_value_to_i8(crv.as_ref(), "crv")? != Some(COSE_CRV_P256) {
                return Err(anyhow::anyhow!("Invalid curve for ES256"));
            }

            let x_bytes = x
                .and_then(|v| match v {
                    Value::Bytes(b) => Some(b),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("Missing x coordinate"))?;
            let y_bytes = y
                .and_then(|v| match v {
                    Value::Bytes(b) => Some(b),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("Missing y coordinate"))?;

            let mut public_key = vec![0x04];
            public_key.extend_from_slice(&x_bytes);
            public_key.extend_from_slice(&y_bytes);

            Ok(ParsedPublicKey {
                algorithm,
                bytes: public_key,
            })
        }
        WebAuthnAlgorithm::EdDsa => {
            if option_value_to_i8(kty.as_ref(), "kty")? != Some(COSE_KTY_OKP) {
                return Err(anyhow::anyhow!("Invalid kty for EdDSA"));
            }
            if option_value_to_i8(crv.as_ref(), "crv")? != Some(COSE_CRV_ED25519) {
                return Err(anyhow::anyhow!("Invalid curve for Ed25519"));
            }

            let x_bytes = x
                .and_then(|v| match v {
                    Value::Bytes(b) => Some(b),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("Missing public key bytes"))?;

            Ok(ParsedPublicKey {
                algorithm,
                bytes: x_bytes,
            })
        }
    }
}

pub fn verify_webauthn_signature(
    algorithm: &WebAuthnAlgorithm,
    public_key_bytes: &[u8],
    signature: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
) -> anyhow::Result<()> {
    let client_data_hash = Sha256::digest(client_data_json);
    let mut signed_bytes = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed_bytes.extend_from_slice(authenticator_data);
    signed_bytes.extend_from_slice(&client_data_hash);

    match algorithm {
        WebAuthnAlgorithm::Es256 => {
            let verifying_key = P256VerifyingKey::from_encoded_point(
                &EncodedPoint::from_bytes(public_key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid P-256 public key: {e}"))?,
            )
            .map_err(|e| anyhow::anyhow!("Invalid P-256 key: {e}"))?;

            let der = P256Signature::from_der(signature).context("Invalid DER signature")?;
            verifying_key
                .verify(&signed_bytes, &der)
                .map_err(|e| anyhow::anyhow!("Invalid signature: {e}"))?
        }
        WebAuthnAlgorithm::EdDsa => {
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                public_key_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 key length"))?,
            )?;
            let sig = Ed25519Signature::try_from(signature)
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 signature length"))?;
            verifying_key
                .verify_strict(&signed_bytes, &sig)
                .map_err(|e| anyhow::anyhow!("Invalid signature: {e}"))?
        }
    }

    Ok(())
}
