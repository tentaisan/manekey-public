use core::ptr;
use embassy_nrf::pac::{KMU_S as KMU, RRAMC_S as RRAMC};
use zeroize::{Zeroize, Zeroizing};

use crate::storage::Nrf54SharedRram;

const POLL_LIMIT: usize = 8_000_000;

#[repr(C, align(16))]
struct PushArea([u8; 16]);
#[unsafe(link_section = ".kmu_product")]
#[unsafe(no_mangle)]
static mut KMU_PUSH_AREA: PushArea = PushArea([0; 16]);

#[repr(C, align(16))]
struct Source {
    value: [u8; 16],
    policy: u32,
    destination: u32,
    metadata: u32,
}

pub use manekey::ctaphid::managed_key_store::ManagedKeyError as Error;

fn clear() {
    KMU.events_error().write_value(0);
    KMU.events_revoked().write_value(0);
    KMU.events_metadataread().write_value(0);
    KMU.events_provisioned().write_value(0);
    KMU.events_pushed().write_value(0);
}

fn wait(event: impl Fn() -> bool) -> Result<(), Error> {
    for _ in 0..POLL_LIMIT {
        if event() {
            return Ok(());
        }
        if KMU.events_error().read() != 0 || KMU.events_revoked().read() != 0 {
            return Err(Error::Hardware);
        }
    }
    Err(Error::Timeout)
}

fn select(slot: u8) {
    KMU.keyslot().write(|w| w.set_id(slot));
    clear();
}

/// Serialized Secure KMU access only; poll limits are iterations, not wall-clock deadlines.
pub fn metadata(slot: u8) -> Result<Option<u32>, Error> {
    select(slot);
    KMU.tasks_readmetadata().write_value(1);
    match wait(|| KMU.events_metadataread().read() != 0) {
        Ok(()) => Ok(Some(KMU.metadata().read())),
        Err(Error::Hardware) if KMU.events_revoked().read() == 0 => Ok(None),
        Err(e) => Err(e),
    }
}

fn mutation(
    rram: &Nrf54SharedRram,
    operation: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    rram.with_controller(|| {
        let saved = RRAMC.config().read();
        RRAMC.config().write(|w| {
            w.set_wen(true);
            w.set_writebufsize(embassy_nrf::pac::rramc::vals::Writebufsize::Unbuffered);
        });
        let result = operation();
        RRAMC.config().write_value(saved);
        result
    })
}

/// Requires exclusive KMU/RRAMC ownership and the linker-reserved Secure push area at 0x20000000.
/// Uses ROTATING assets; failed busy DMA resets the CPU before releasing stack input.
pub fn provision(
    rram: &Nrf54SharedRram,
    slot: u8,
    owner: u32,
    value: &[u8; 16],
) -> Result<(), Error> {
    if metadata(slot)?.is_some() {
        return Err(Error::ForeignAsset);
    }
    let mut source = Source {
        value: *value,
        policy: 1,
        destination: ptr::addr_of_mut!(KMU_PUSH_AREA) as u32,
        metadata: owner,
    };

    assert_eq!(source.destination, 0x2000_0000);
    select(slot);
    KMU.src().write_value(&source as *const Source as u32);
    cortex_m::asm::dmb();
    let result = mutation(rram, || {
        KMU.tasks_provision().write_value(1);
        wait(|| KMU.events_provisioned().read() != 0)
    });

    if result.is_err() && KMU.status().read().status() == embassy_nrf::pac::kmu::vals::Status::Busy
    {
        cortex_m::peripheral::SCB::sys_reset();
    }
    source.value.zeroize();
    result
}

/// Expands an owned asset into CPU-readable Secure RAM, not a protected-key crypto operation.
pub fn push(slot: u8, owner: u32) -> Result<Zeroizing<[u8; 16]>, Error> {
    match metadata(slot)? {
        Some(actual) if actual == owner => {}
        Some(_) => return Err(Error::ForeignAsset),
        None => return Err(Error::MissingAsset),
    }
    unsafe { ptr::write_volatile(ptr::addr_of_mut!(KMU_PUSH_AREA.0), [0; 16]) };
    select(slot);
    KMU.tasks_push().write_value(1);
    let result = wait(|| KMU.events_pushed().read() != 0);
    cortex_m::asm::dmb();
    let value = unsafe { ptr::read_volatile(ptr::addr_of!(KMU_PUSH_AREA.0)) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!(KMU_PUSH_AREA.0), [0; 16]) };
    result?;
    Ok(Zeroizing::new(value))
}

/// Revoke only owned ROTATING assets under the same serialized Secure controller ownership.
pub fn revoke(rram: &Nrf54SharedRram, slot: u8, owner: u32) -> Result<(), Error> {
    match metadata(slot)? {
        None => return Ok(()),
        Some(actual) if actual == owner => {}
        Some(_) => return Err(Error::ForeignAsset),
    }
    select(slot);
    mutation(rram, || {
        KMU.tasks_revoke().write_value(1);
        wait(|| KMU.events_revoked().read() != 0)
    })?;
    if metadata(slot)?.is_some() {
        return Err(Error::Hardware);
    }
    Ok(())
}
