//! Utilities for converting between key formats (SPKI/DER to COSE).
//!
//! KMS returns public keys as DER-encoded SubjectPublicKeyInfo (SPKI).
//! WebAuthn requires COSE-encoded public keys. This module handles the conversion.

use coset::iana;
use coset::CoseKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;

/// Errors that can occur during key format conversion.
#[derive(Debug, thiserror::Error)]
pub enum CoseConversionError {
    /// Failed to parse the DER-encoded SPKI public key.
    #[error("failed to parse DER SPKI public key: {0}")]
    InvalidSpki(#[from] p256::pkcs8::spki::Error),
}

/// Convert a DER-encoded SPKI public key (as returned by KMS GetPublicKey)
/// to a COSE key suitable for WebAuthn attestation.
///
/// The conversion:
/// 1. Parses the DER SPKI with `p256::PublicKey`
/// 2. Extracts uncompressed EC point (0x04 || x || y)
/// 3. Builds a `coset::CoseKey` with EC2 P-256 parameters and ES256 algorithm
pub fn spki_der_to_cose_key(der_bytes: &[u8]) -> Result<CoseKey, CoseConversionError> {
    let public_key = PublicKey::from_public_key_der(der_bytes)?;
    Ok(p256_public_key_to_cose_key(&public_key))
}

/// Convert a `p256::PublicKey` to a COSE key.
fn p256_public_key_to_cose_key(public_key: &PublicKey) -> CoseKey {
    let encoded_point = public_key.to_encoded_point(false);
    let x = encoded_point
        .x()
        .expect("uncompressed point has x")
        .to_vec();
    let y = encoded_point
        .y()
        .expect("uncompressed point has y")
        .to_vec();

    coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
        .algorithm(iana::Algorithm::ES256)
        .build()
}

/// Extract the raw x and y coordinates from a DER-encoded SPKI public key.
///
/// Returns `(x, y)` where each is a 32-byte big-endian coordinate.
#[cfg(test)]
fn spki_der_to_coordinates(
    der_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32]), CoseConversionError> {
    let public_key = PublicKey::from_public_key_der(der_bytes)?;
    let encoded_point = public_key.to_encoded_point(false);
    let x = encoded_point.x().expect("uncompressed point has x");
    let y = encoded_point.y().expect("uncompressed point has y");

    let mut x_arr = [0u8; 32];
    let mut y_arr = [0u8; 32];
    x_arr.copy_from_slice(x);
    y_arr.copy_from_slice(y);

    Ok((x_arr, y_arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::iana::EnumI64;
    use p256::ecdsa::SigningKey;

    /// Helper to find a parameter value by label in a CoseKey's params vec.
    fn find_param<'a>(
        params: &'a [(coset::Label, ciborium::Value)],
        label: &coset::Label,
    ) -> Option<&'a ciborium::Value> {
        params.iter().find(|(l, _)| l == label).map(|(_, v)| v)
    }

    /// Generate a test P-256 key pair and return the public key in SPKI DER format.
    fn generate_test_spki_der() -> (SigningKey, Vec<u8>) {
        use p256::pkcs8::EncodePublicKey;
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let public_key = signing_key.verifying_key().to_public_key_der().unwrap();
        (signing_key, public_key.to_vec())
    }

    #[test]
    fn spki_to_cose_roundtrip() {
        let (_sk, der) = generate_test_spki_der();
        let cose_key = spki_der_to_cose_key(&der).unwrap();

        // Verify key type is EC2
        assert_eq!(cose_key.kty, coset::KeyType::Assigned(iana::KeyType::EC2));

        // Verify algorithm is ES256
        assert_eq!(
            cose_key.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
        );

        // Curve parameter (-1) should be P-256 (1)
        let curve_label = coset::Label::Int(iana::Ec2KeyParameter::Crv.to_i64());
        let curve_value = find_param(&cose_key.params, &curve_label).expect("missing curve param");
        assert_eq!(
            *curve_value,
            ciborium::Value::Integer(iana::EllipticCurve::P_256.to_i64().into())
        );

        // X coordinate should be 32 bytes
        let x_label = coset::Label::Int(iana::Ec2KeyParameter::X.to_i64());
        let x_value = find_param(&cose_key.params, &x_label).expect("missing x param");
        if let ciborium::Value::Bytes(x_bytes) = x_value {
            assert_eq!(x_bytes.len(), 32);
        } else {
            panic!("x param is not bytes");
        }

        // Y coordinate should be 32 bytes
        let y_label = coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64());
        let y_value = find_param(&cose_key.params, &y_label).expect("missing y param");
        if let ciborium::Value::Bytes(y_bytes) = y_value {
            assert_eq!(y_bytes.len(), 32);
        } else {
            panic!("y param is not bytes");
        }
    }

    #[test]
    fn spki_to_coordinates_roundtrip() {
        let (_sk, der) = generate_test_spki_der();
        let (x, y) = spki_der_to_coordinates(&der).unwrap();

        // Both should be 32 bytes (enforced by the array type)
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);

        // The coordinates should match what we get from the COSE key
        let cose_key = spki_der_to_cose_key(&der).unwrap();

        let x_label = coset::Label::Int(iana::Ec2KeyParameter::X.to_i64());
        if let Some(ciborium::Value::Bytes(x_bytes)) = find_param(&cose_key.params, &x_label) {
            assert_eq!(x_bytes.as_slice(), &x[..]);
        } else {
            panic!("missing or wrong type for x param");
        }

        let y_label = coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64());
        if let Some(ciborium::Value::Bytes(y_bytes)) = find_param(&cose_key.params, &y_label) {
            assert_eq!(y_bytes.as_slice(), &y[..]);
        } else {
            panic!("missing or wrong type for y param");
        }
    }

    #[test]
    fn invalid_der_returns_error() {
        let result = spki_der_to_cose_key(&[0x00, 0x01, 0x02]);
        assert!(result.is_err());
    }
}
