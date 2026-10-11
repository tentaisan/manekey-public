use crate::ctaphid::cbor;
use crate::ctaphid::credential::CredentialProtection;

/// Caller establishes UP/UV; writes generic zero-AAGUID attested data.
/// None may leave partially written output.
pub fn write_attested_authenticator_data<'a>(
    buf: &'a mut [u8],
    rp_id_hash: &[u8; 32],
    credential_id: &[u8],
    public_key_x: &[u8; 32],
    public_key_y: &[u8; 32],
    cred_protect: Option<CredentialProtection>,
    hmac_secret: Option<bool>,
    cred_blob: Option<bool>,
    user_verified: bool,
) -> Option<&'a [u8]> {
    let mut offset = 0;

    if buf.len() < 37 {
        return None;
    }

    buf[offset..offset + 32].copy_from_slice(rp_id_hash);
    offset += 32;

    let has_extensions = cred_protect.is_some() || hmac_secret.is_some() || cred_blob.is_some();
    buf[offset] =
        0x41 | if user_verified { 0x04 } else { 0 } | if has_extensions { 0x80 } else { 0 };
    offset += 1;

    buf[offset..offset + 4].copy_from_slice(&0u32.to_be_bytes());
    offset += 4;

    if buf.len() < offset + 16 + 2 + credential_id.len() {
        return None;
    }

    buf[offset..offset + 16].copy_from_slice(&[0u8; 16]);
    offset += 16;

    if credential_id.len() > 0xffff {
        return None;
    }

    let cred_len = credential_id.len() as u16;
    buf[offset..offset + 2].copy_from_slice(&cred_len.to_be_bytes());
    offset += 2;

    buf[offset..offset + credential_id.len()].copy_from_slice(credential_id);
    offset += credential_id.len();

    let cose_key = write_cose_key(&mut buf[offset..], public_key_x, public_key_y)?;
    offset += cose_key.len();

    if has_extensions {
        let extension_output = write_make_credential_extensions(
            &mut buf[offset..],
            cred_protect,
            hmac_secret,
            cred_blob,
        )?;
        offset += extension_output.len();
    }

    Some(&buf[..offset])
}

/// Caller validates the supplied COSE key and establishes UP/UV.
/// None may leave partially written output.
pub fn write_attested_authenticator_data_with_cose_key<'a>(
    buf: &'a mut [u8],
    rp_id_hash: &[u8; 32],
    credential_id: &[u8],
    credential_public_key: &[u8],
    cred_protect: Option<CredentialProtection>,
    hmac_secret: Option<bool>,
    cred_blob: Option<bool>,
    user_verified: bool,
) -> Option<&'a [u8]> {
    let has_extensions = cred_protect.is_some() || hmac_secret.is_some() || cred_blob.is_some();
    let fixed_len = 37usize
        .checked_add(16 + 2)?
        .checked_add(credential_id.len())?
        .checked_add(credential_public_key.len())?;
    if credential_id.len() > u16::MAX as usize || buf.len() < fixed_len {
        return None;
    }

    buf[..32].copy_from_slice(rp_id_hash);
    buf[32] = 0x41 | if user_verified { 0x04 } else { 0 } | if has_extensions { 0x80 } else { 0 };
    buf[33..37].copy_from_slice(&0u32.to_be_bytes());

    let mut offset = 37;
    buf[offset..offset + 16].fill(0);
    offset += 16;
    buf[offset..offset + 2].copy_from_slice(&(credential_id.len() as u16).to_be_bytes());
    offset += 2;
    buf[offset..offset + credential_id.len()].copy_from_slice(credential_id);
    offset += credential_id.len();
    buf[offset..offset + credential_public_key.len()].copy_from_slice(credential_public_key);
    offset += credential_public_key.len();

    if has_extensions {
        let extension_output = write_make_credential_extensions(
            &mut buf[offset..],
            cred_protect,
            hmac_secret,
            cred_blob,
        )?;
        offset += extension_output.len();
    }

    Some(&buf[..offset])
}

fn write_make_credential_extensions<'a>(
    buf: &'a mut [u8],
    cred_protect: Option<CredentialProtection>,
    hmac_secret: Option<bool>,
    cred_blob: Option<bool>,
) -> Option<&'a [u8]> {
    let mut w = cbor::Writer::new(buf);
    w.write_map_len(
        u8::from(cred_protect.is_some())
            + u8::from(hmac_secret.is_some())
            + u8::from(cred_blob.is_some()),
    )?;

    if let Some(stored) = cred_blob {
        w.write_text(b"credBlob")?;
        w.write_bool(stored)?;
    }
    if let Some(protection) = cred_protect {
        w.write_text(b"credProtect")?;
        w.write_uint(protection.ctap_value() as u64)?;
    }
    if let Some(enabled) = hmac_secret {
        w.write_text(b"hmac-secret")?;
        w.write_bool(enabled)?;
    }
    Some(w.finish())
}

pub fn write_cose_key<'a>(
    buf: &'a mut [u8],
    public_key_x: &[u8; 32],
    public_key_y: &[u8; 32],
) -> Option<&'a [u8]> {
    let mut w = cbor::Writer::new(buf);

    w.write_map_len(5)?;

    w.write_uint(1)?;
    w.write_uint(2)?;

    w.write_uint(3)?;
    w.write_negint(-7)?;

    w.write_negint(-1)?;
    w.write_uint(1)?;

    w.write_negint(-2)?;
    w.write_bytes(public_key_x)?;

    w.write_negint(-3)?;
    w.write_bytes(public_key_y)?;

    Some(w.finish())
}

/// Caller establishes UP/UV and supplies the persisted counter.
pub fn write_assertion_authenticator_data<'a>(
    buf: &'a mut [u8],
    rp_id_hash: &[u8; 32],
    sign_count: u32,
    user_verified: bool,
) -> Option<&'a [u8]> {
    write_assertion_authenticator_data_with_hmac_secret(
        buf,
        rp_id_hash,
        sign_count,
        user_verified,
        None,
        None,
    )
}

/// Caller establishes UP/UV; None may leave partially written output.
pub fn write_assertion_authenticator_data_with_hmac_secret<'a>(
    buf: &'a mut [u8],
    rp_id_hash: &[u8; 32],
    sign_count: u32,
    user_verified: bool,
    hmac_secret: Option<&[u8]>,
    cred_blob: Option<&[u8]>,
) -> Option<&'a [u8]> {
    if buf.len() < 37 {
        return None;
    }

    buf[0..32].copy_from_slice(rp_id_hash);

    let has_extensions = hmac_secret.is_some() || cred_blob.is_some();
    buf[32] = 0x01 | if user_verified { 0x04 } else { 0 } | if has_extensions { 0x80 } else { 0 };

    buf[33..37].copy_from_slice(&sign_count.to_be_bytes());

    let mut offset = 37;
    if has_extensions {
        let mut w = cbor::Writer::new(&mut buf[offset..]);
        w.write_map_len(u8::from(hmac_secret.is_some()) + u8::from(cred_blob.is_some()))?;
        if let Some(blob) = cred_blob {
            w.write_text(b"credBlob")?;
            w.write_bytes(blob)?;
        }
        if let Some(output) = hmac_secret {
            w.write_text(b"hmac-secret")?;
            w.write_bytes(output)?;
        }
        offset += w.finish().len();
    }

    Some(&buf[..offset])
}
