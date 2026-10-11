use crate::{
    crypto::CracenP256,
    kmu::{self, Error},
    storage::Nrf54SharedRram,
};
use manekey::ctaphid::{
    crypto,
    entropy::EntropySource,
    managed_key_store::{KeyPersistenceProtection, ManagedPrivateKeyStore, RamKeyStorage},
    storage::MAX_RECORDS,
};
use zeroize::Zeroizing;

const ROOT_BASE: u8 = 100;
const GROUP_BASE: u8 = 104;
const ROOT_OWNER: u32 = 0x4d4b_5200;
const GROUP_OWNER: u32 = 0x4d4b_4300;
const ROOT_CONTROL: [u8; 16] = *b"MK-FIDO-ROOT-v01";
const _: () = assert!(MAX_RECORDS == 14);
const _: () = assert!(GROUP_BASE as usize + MAX_RECORDS * 3 <= 180);

pub type KmuKeyStore = ManagedPrivateKeyStore<KmuAssets, CracenP256>;
/// FIDO-owned ROTATING KMU slots; private values expand into Secure RAM for use.
pub struct KmuAssets {
    rram: &'static Nrf54SharedRram,
}

fn group_slot(index: usize, part: u8) -> u8 {
    GROUP_BASE + (index as u8) * 3 + part
}
fn group_owner(index: usize, part: u8) -> u32 {
    GROUP_OWNER | ((index as u32) << 4) | u32::from(part)
}
fn check_index(index: usize) -> Result<(), Error> {
    if index < MAX_RECORDS {
        Ok(())
    } else {
        Err(Error::InvalidHandle)
    }
}

/// Exclusively reserve the product KMU slots, push area and RRAM/crypto service.
/// Initial provisioning requires authorized empty credential media; partial errors are not atomic rollback.
pub fn open<E: EntropySource>(
    rram: &'static Nrf54SharedRram,
    entropy: &mut E,
    empty_journal: bool,
) -> Result<KmuKeyStore, Error> {
    let control = kmu::metadata(ROOT_BASE + 2)?;
    if control.is_none() {
        #[cfg(not(feature = "kmu-key-setup"))]
        return Err(Error::MissingAsset);
        #[cfg(feature = "kmu-key-setup")]
        {
            if !empty_journal {
                return Err(Error::InvalidHandle);
            }
            for part in 0..2 {
                kmu::revoke(rram, ROOT_BASE + part, ROOT_OWNER + u32::from(part))?;
            }
            let root: Zeroizing<[u8; 32]> =
                Zeroizing::new(crypto::generate_random_bytes(entropy).ok_or(Error::Entropy)?);
            kmu::provision(rram, ROOT_BASE, ROOT_OWNER, root[..16].try_into().unwrap())?;
            kmu::provision(
                rram,
                ROOT_BASE + 1,
                ROOT_OWNER + 1,
                root[16..].try_into().unwrap(),
            )?;
            kmu::provision(rram, ROOT_BASE + 2, ROOT_OWNER + 2, &ROOT_CONTROL)?;
        }
    } else if control != Some(ROOT_OWNER + 2) {
        return Err(Error::ForeignAsset);
    }
    let _ = (entropy, empty_journal);
    if *kmu::push(ROOT_BASE + 2, ROOT_OWNER + 2)? != ROOT_CONTROL {
        return Err(Error::ForeignAsset);
    }
    let mut root = Zeroizing::new([0; 32]);
    root[..16].copy_from_slice(&*kmu::push(ROOT_BASE, ROOT_OWNER)?);
    root[16..].copy_from_slice(&*kmu::push(ROOT_BASE + 1, ROOT_OWNER + 1)?);

    ManagedPrivateKeyStore::new(
        KmuAssets { rram },
        root,
        CracenP256,
        b"manekey-fido-kmu-handle-v1",
        b"manekey-fido-kmu-cred-random-v1",
    )
}

impl RamKeyStorage for KmuAssets {
    fn capacity(&self) -> usize {
        MAX_RECORDS
    }
    fn protection(&self) -> KeyPersistenceProtection {
        KeyPersistenceProtection::HardwareAccessControlled
    }

    fn nonce(&mut self, index: usize) -> Result<Option<[u8; 16]>, Error> {
        check_index(index)?;
        match kmu::metadata(group_slot(index, 2))? {
            None => Ok(None),
            Some(owner) if owner == group_owner(index, 2) => {
                Ok(Some(*kmu::push(group_slot(index, 2), owner)?))
            }
            Some(_) => Err(Error::ForeignAsset),
        }
    }

    fn load_private(&mut self, index: usize) -> Result<Zeroizing<[u8; 32]>, Error> {
        check_index(index)?;
        if self.nonce(index)?.is_none() {
            return Err(Error::MissingAsset);
        }
        let mut scalar = Zeroizing::new([0; 32]);
        for part in 0..2 {
            scalar[usize::from(part) * 16..usize::from(part + 1) * 16].copy_from_slice(
                &*kmu::push(group_slot(index, part), group_owner(index, part))?,
            );
        }
        Ok(scalar)
    }

    fn provision(
        &mut self,
        index: usize,
        private: &[u8; 32],
        nonce: &[u8; 16],
    ) -> Result<(), Error> {
        check_index(index)?;
        if self.nonce(index)?.is_some() {
            return Err(Error::ForeignAsset);
        }
        if !crypto::p256_private_scalar_is_valid(private) {
            return Err(Error::InvalidHandle);
        }
        for part in 0..2 {
            kmu::provision(
                self.rram,
                group_slot(index, part),
                group_owner(index, part),
                private[usize::from(part) * 16..usize::from(part + 1) * 16]
                    .try_into()
                    .unwrap(),
            )?;
        }

        kmu::provision(
            self.rram,
            group_slot(index, 2),
            group_owner(index, 2),
            nonce,
        )
    }

    fn release(&mut self, index: usize) -> Result<(), Error> {
        check_index(index)?;
        for part in [2, 0, 1] {
            kmu::revoke(self.rram, group_slot(index, part), group_owner(index, part))?;
        }
        Ok(())
    }
}
