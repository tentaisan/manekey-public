

use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};
use trusted_boundary::{operation, status};


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayResult {
    pub status: u32,
    pub response_len: u32,
}

impl GatewayResult {
    const fn new(status: u32, response_len: usize) -> Self {
        Self {
            status,
            response_len: response_len as u32,
        }
    }
}


pub fn dispatch<T: TrustedBackend>(
    trusted: &mut T,
    operation_code: u32,
    request: &[u8],
    response: &mut [u8],
) -> GatewayResult {
    let result = match operation_code {
        operation::SUBMIT_CBOR => trusted.submit_cbor(request),
        operation::SUBMIT_U2F => trusted.submit_u2f(request),
        operation::POLL => match trusted.poll() {
            Some(result) => result,
            None => return GatewayResult::new(status::BUSY, 0),
        },
        operation::CANCEL => {
            trusted.cancel();
            return GatewayResult::new(status::OK, 0);
        }
        _ => return GatewayResult::new(status::INVALID_OPERATION, 0),
    };

    match result {
        TrustedResult::Response(data) => {
            if data.len() > response.len() {
                GatewayResult::new(status::OUTPUT_TOO_SMALL, 0)
            } else {
                response[..data.len()].copy_from_slice(data);
                GatewayResult::new(status::OK, data.len())
            }
        }
        TrustedResult::UserPresencePending => GatewayResult::new(status::USER_PRESENCE_PENDING, 0),
        TrustedResult::Busy => GatewayResult::new(status::BUSY, 0),
        TrustedResult::InvalidRequest => GatewayResult::new(status::INVALID_REQUEST, 0),
    }
}


















































































