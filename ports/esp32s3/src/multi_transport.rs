use manekey::frontend::ingress::{IngressId, IngressKind};
#[cfg(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
use manekey::{
    boundary::{mailbox::LocalMailboxTransport, mailbox_backend::MailboxTrustedBackend},
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
};

#[cfg(all(
    not(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core")),
    feature = "up-always-present"
))]
use crate::fido::EspAlwaysSharedTrustedDispatcher;
#[cfg(all(
    not(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core")),
    not(feature = "up-always-present")
))]
use crate::fido::EspSharedTrustedDispatcher;
use crate::{
    ble_fido::BLE_PACKET_LEN,
    ble_ingress::SharedBleIngressFrontend,
    usb_ingress::{SharedArbiter as GenericSharedArbiter, UsbIngressFrontend},
};

#[cfg(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
pub(crate) type SelectedBackend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;
#[cfg(all(
    not(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core")),
    not(feature = "up-always-present")
))]
pub(crate) type SelectedBackend = EspSharedTrustedDispatcher;
#[cfg(all(
    not(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core")),
    feature = "up-always-present"
))]
pub(crate) type SelectedBackend = EspAlwaysSharedTrustedDispatcher;

const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);
/// Cooperative transport ownership, not PMS isolation; NoopRawMutex excludes neither IRQ nor other-core access.
pub type SharedArbiter = GenericSharedArbiter<SelectedBackend>;
pub type MultiUsbFrontend = UsbIngressFrontend<SelectedBackend>;
pub type MultiBleFrontend = SharedBleIngressFrontend<SelectedBackend>;
#[cfg(feature = "managed-internal-uart")]
pub type MultiInternalFrontend<const MAX: usize> =
    crate::internal_ingress::SharedInternalIngressFrontend<SelectedBackend, MAX>;

pub const fn build_ble_frontend(arbiter: &'static SharedArbiter) -> MultiBleFrontend {
    MultiBleFrontend::new(BLE_PACKET_LEN, BLE_INGRESS, arbiter)
}
