use crate::ctaphid::cbor;

pub fn write_packed_attestation_object(
    w: &mut cbor::Writer<'_>,
    auth_data: &[u8],
    signature: &[u8],
) -> Option<()> {
    write_packed_attestation_object_with_algorithm(w, auth_data, signature, -7)
}

/// Writes self attestation without a device or manufacturer identity certificate.
pub fn write_packed_attestation_object_with_algorithm(
    w: &mut cbor::Writer<'_>,
    auth_data: &[u8],
    signature: &[u8],
    cose_algorithm: i8,
) -> Option<()> {
    w.write_map_len(3)?;

    w.write_uint(1)?;
    w.write_text(b"packed")?;

    w.write_uint(2)?;
    w.write_bytes(auth_data)?;

    w.write_uint(3)?;
    w.write_map_len(2)?;

    w.write_text(b"alg")?;
    w.write_negint(cose_algorithm)?;

    w.write_text(b"sig")?;
    w.write_bytes(signature)?;

    Some(())
}
