//! Deterministic age X25519 keypair derivation from a passphrase.
//!
//! Intended to produce identical output to CrabShack's TypeScript implementation at
//! `orchestrator-api/src/backup/age-identity.ts`.
//!
//! Algorithm:
//! 1. HKDF-SHA256(salt="crabshack", ikm=passphrase, info="age-keypair-v2:{instanceName}") -> 32-byte seed
//! 2. X25519 scalar multiplication: public_key = seed * basepoint
//! 3. recipient = bech32_encode("age", public_key_bytes)
//! 4. identity = bech32_encode("age-secret-key-", seed).to_uppercase()

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Bech32 character set (BIP173)
const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, gen) in BECH32_GEN.iter().enumerate() {
            if (top >> i) & 1 != 0 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut r = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        r.push(c >> 5);
    }
    r.push(0);
    for c in hrp.bytes() {
        r.push(c & 31);
    }
    r
}

fn convert_bits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for &b in data {
        acc = (acc << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let dp = convert_bits_8_to_5(data);
    let lhrp = hrp.to_lowercase();
    let hrp_expanded = bech32_hrp_expand(&lhrp);

    let mut values = hrp_expanded;
    values.extend_from_slice(&dp);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    let pm = bech32_polymod(&values) ^ 1;

    let mut result = lhrp;
    result.push('1');
    for &v in &dp {
        result.push(BECH32_CHARSET[v as usize] as char);
    }
    for i in 0..6 {
        let idx = ((pm >> (5 * (5 - i))) & 31) as usize;
        result.push(BECH32_CHARSET[idx] as char);
    }
    result
}

/// HKDF-SHA256 Extract + Expand (single-block, 32-byte output).
///
/// Matches the TypeScript: `createHmac("sha256", salt).update(ikm).digest()` for PRK,
/// then `createHmac("sha256", prk).update(info || 0x01).digest()[0..32]` for OKM.
fn hkdf_sha256(ikm: &str, salt: &str, info: &str) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(key=salt, data=ikm)
    let mut mac =
        HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC accepts any key length");
    mac.update(ikm.as_bytes());
    let prk = mac.finalize().into_bytes();

    // Expand: OKM = HMAC-SHA256(key=PRK, data=(info || 0x01))[0..32]
    let mut mac =
        HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key length");
    mac.update(info.as_bytes());
    mac.update(&[0x01]);
    let okm = mac.finalize().into_bytes();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&okm[..32]);
    seed
}

/// Derive a deterministic age X25519 keypair from a passphrase and instance name.
///
/// Returns `(recipient, identity)` where:
/// - `recipient` is the bech32-encoded public key (e.g., "age1...")
/// - `identity` is the bech32-encoded seed (e.g., "AGE-SECRET-KEY-1...")
pub fn derive_age_keypair(passphrase: &str, instance_name: &str) -> (String, String) {
    let info = format!("age-keypair-v2:{}", instance_name);
    let seed = hkdf_sha256(passphrase, "crabshack", &info);

    // X25519: derive public key from seed (used as static secret / scalar)
    let secret = x25519_dalek::StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    let public_bytes = public.as_bytes();

    let recipient = bech32_encode("age", public_bytes);
    let identity = bech32_encode("age-secret-key-", &seed).to_uppercase();

    (recipient, identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_deterministic() {
        let seed1 = hkdf_sha256("pass", "crabshack", "age-keypair-v2:test");
        let seed2 = hkdf_sha256("pass", "crabshack", "age-keypair-v2:test");
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_hkdf_different_inputs() {
        let seed1 = hkdf_sha256("pass1", "crabshack", "age-keypair-v2:test");
        let seed2 = hkdf_sha256("pass2", "crabshack", "age-keypair-v2:test");
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_derive_age_keypair_format() {
        let (recipient, identity) = derive_age_keypair("test-passphrase", "my-instance");
        assert!(recipient.starts_with("age1"), "recipient should start with 'age1': {}", recipient);
        assert!(
            identity.starts_with("AGE-SECRET-KEY-1"),
            "identity should start with 'AGE-SECRET-KEY-1': {}",
            identity
        );
    }

    #[test]
    fn test_derive_age_keypair_deterministic() {
        let (r1, i1) = derive_age_keypair("pass", "inst");
        let (r2, i2) = derive_age_keypair("pass", "inst");
        assert_eq!(r1, r2);
        assert_eq!(i1, i2);
    }

    #[test]
    fn test_derive_age_keypair_different_instances() {
        let (r1, _) = derive_age_keypair("pass", "inst-a");
        let (r2, _) = derive_age_keypair("pass", "inst-b");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_golden_vector_1() {
        let (r, i) = derive_age_keypair("test-passphrase", "golden-test-instance");
        assert_eq!(r, "age1x96uqc6ucwvsfeqj0p83dme4ve76xj6jh9v5q2tcez8efqg7g9zs9kdp0y");
        assert_eq!(i, "AGE-SECRET-KEY-1S6ZSMWVK9M6MRMRQW5V5G099ZDK4PHKE9HD3QKM527E5ET4D0Y3S8GVUCK");
    }

    #[test]
    fn test_golden_vector_2() {
        let (r, i) = derive_age_keypair("abc123def456", "mighty-jay");
        assert_eq!(r, "age1shyzgr34w6cw4kkp9pny725cduu7u3xfntx79u8nzgzseh0pyguqnr882m");
        assert_eq!(i, "AGE-SECRET-KEY-1HDD0KF7VU5HWEF4VS96Q5EQQFDXH8E8A7VN75YWGC8WZ73AZTVZQJ7V8SU");
    }

    #[test]
    fn test_golden_vector_3_empty_passphrase() {
        let (r, i) = derive_age_keypair("", "empty-passphrase");
        assert_eq!(r, "age1xhfpav4rtg4286njkse6akpwyq6l80xgw7tw5cxz5m3k46l99plqp6mzke");
        assert_eq!(i, "AGE-SECRET-KEY-13ZNRYFR3X7RQUZNNCP6FCCAJ73X82F2WUUSM3MS8NG5A8LJ90L8S46PSE5");
    }

    #[test]
    fn test_golden_vector_4_special_chars() {
        let (r, i) = derive_age_keypair("a]very/long+passphrase!with@special#chars$", "special-chars-test");
        assert_eq!(r, "age12ayk7rn78uujvqp4a7cae42g6hvzjx8dgkrgcc6zulq32ffmq3ts0npdgp");
        assert_eq!(i, "AGE-SECRET-KEY-169JM43WKP2FSJ3XX6VZA6DYHPP0TTYJUPH9UNAJ72XS4TDCX5ATQY4GGMT");
    }

    #[test]
    fn test_bech32_encode_roundtrip_format() {
        // Verify bech32 encoding produces valid-looking output
        let data = [0u8; 32];
        let encoded = bech32_encode("age", &data);
        assert!(encoded.starts_with("age1"));
        // age1 + 52 data chars + 6 checksum chars = 62 total for 32-byte input
        // 32 bytes = 256 bits -> ceil(256/5) = 52 5-bit groups
        assert_eq!(encoded.len(), 4 + 52 + 6); // "age1" prefix + data + checksum
    }
}
