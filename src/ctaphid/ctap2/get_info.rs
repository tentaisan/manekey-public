use crate::ctaphid::cbor;
use crate::ctaphid::pin_uv_auth::PinUvAuthProvider;

use super::capabilities::CURRENT;
use super::status;

pub(super) fn get_info<'a, A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
) -> &'a [u8] {
    get_info_with_transports(pin_uv_auth, buf, CURRENT.transports)
}

pub(super) fn get_info_with_transports<'a, A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
    transports: &[&[u8]],
) -> &'a [u8] {
    get_info_with_transports_and_algorithms(pin_uv_auth, buf, transports, false)
}

/// Writes configured capabilities; panics if the output buffer is too small.
pub(super) fn get_info_with_transports_and_algorithms<'a, A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
    transports: &[&[u8]],
    supports_ml_dsa_44: bool,
) -> &'a [u8] {
    let mut w = cbor::Writer::new(buf);
    let supports_client_pin = pin_uv_auth.supports_pin_setting();

    w.write_raw_u8(status::OK).unwrap();

    w.write_map_len(9 + u8::from(supports_client_pin) + u8::from(cfg!(feature = "cred-blob")))
        .unwrap();

    w.write_uint(1).unwrap();
    w.write_array_len(CURRENT.versions.len() as u8).unwrap();
    for version in CURRENT.versions {
        w.write_text(version).unwrap();
    }

    w.write_uint(2).unwrap();
    w.write_array_len(CURRENT.extensions.len() as u8).unwrap();
    for extension in CURRENT.extensions {
        w.write_text(extension).unwrap();
    }

    w.write_uint(3).unwrap();
    w.write_bytes(&CURRENT.aaguid).unwrap();

    w.write_uint(4).unwrap();
    w.write_map_len(2 + u8::from(CURRENT.user_verification) + (u8::from(supports_client_pin) * 3))
        .unwrap();

    w.write_text(b"rk").unwrap();
    w.write_bool(CURRENT.resident_key).unwrap();

    w.write_text(b"up").unwrap();
    w.write_bool(CURRENT.user_presence).unwrap();

    if CURRENT.user_verification {
        w.write_text(b"uv").unwrap();
        w.write_bool(true).unwrap();
    }

    if supports_client_pin {
        w.write_text(b"credMgmt").unwrap();
        w.write_bool(true).unwrap();

        w.write_text(b"clientPin").unwrap();
        w.write_bool(pin_uv_auth.pin_is_set()).unwrap();

        w.write_text(b"pinUvAuthToken").unwrap();
        w.write_bool(true).unwrap();
    }

    w.write_uint(5).unwrap();

    w.write_uint(CURRENT.max_message_size() as u64).unwrap();

    if supports_client_pin {
        w.write_uint(6).unwrap();
        let protocols = pin_uv_auth.supported_pin_protocols();
        w.write_array_len(protocols.len() as u8).unwrap();
        for &protocol in protocols {
            w.write_uint(protocol as u64).unwrap();
        }
    }

    w.write_uint(7).unwrap();
    w.write_uint(CURRENT.max_credential_count() as u64).unwrap();

    w.write_uint(8).unwrap();
    w.write_uint(CURRENT.max_credential_id_length() as u64)
        .unwrap();

    w.write_uint(9).unwrap();
    w.write_array_len(transports.len() as u8).unwrap();
    for transport in transports {
        w.write_text(transport).unwrap();
    }

    w.write_uint(10).unwrap();
    w.write_array_len(1 + u8::from(supports_ml_dsa_44)).unwrap();
    write_pub_key_cred_param(&mut w, -7).unwrap();
    if supports_ml_dsa_44 {
        write_pub_key_cred_param(&mut w, -48).unwrap();
    }

    if cfg!(feature = "cred-blob") {
        w.write_uint(15).unwrap();
        w.write_uint(CURRENT.max_cred_blob_length() as u64).unwrap();
    }

    w.finish()
}

fn write_pub_key_cred_param(w: &mut cbor::Writer<'_>, algorithm: i8) -> Option<()> {
    w.write_map_len(2)?;

    w.write_text(b"alg")?;
    w.write_negint(algorithm)?;

    w.write_text(b"type")?;
    w.write_text(b"public-key")?;

    Some(())
}
