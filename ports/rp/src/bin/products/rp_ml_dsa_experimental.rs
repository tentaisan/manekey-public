#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
use core::alloc::{GlobalAlloc, Layout};

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
use embedded_alloc::LlffHeap as Heap;

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
const ML_DSA_HEAP_SIZE: usize = 96 * 1024;

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
struct ProductHeap(Heap);

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
impl ProductHeap {
    const fn empty() -> Self {
        Self(Heap::empty())
    }

    unsafe fn init(&self, start_addr: usize, size: usize) {
        unsafe { self.0.init(start_addr, size) };
    }
}

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
unsafe impl GlobalAlloc for ProductHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let allocation = unsafe { GlobalAlloc::alloc(&self.0, layout) };

        allocation
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { GlobalAlloc::dealloc(&self.0, ptr, layout) };
    }
}

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
#[global_allocator]
static ML_DSA_HEAP: ProductHeap = ProductHeap::empty();

#[cfg(all(
    feature = "experimental-ml-dsa-rustcrypto",
    feature = "experimental-ml-dsa-fips204"
))]
compile_error!("select only one RP ML-DSA credential backend");

#[cfg(not(any(
    feature = "experimental-ml-dsa-rustcrypto",
    feature = "experimental-ml-dsa-fips204"
)))]
compile_error!("select an RP ML-DSA credential backend");

#[cfg(all(
    feature = "experimental-ml-dsa-rustcrypto",
    not(feature = "experimental-ml-dsa-fips204")
))]
type SelectedMlDsa44 = manekey::ctaphid::pqc_signature::SoftwareMlDsa44;

#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    not(feature = "experimental-ml-dsa-rustcrypto"),
    feature = "chip-rp235xa"
))]
type SelectedMlDsa44 = manekey_rp::platform::rp::crypto::MlDsa;

#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    not(feature = "experimental-ml-dsa-rustcrypto"),
    not(feature = "chip-rp235xa")
))]
type SelectedMlDsa44 = manekey_rp::platform::rp::crypto::MlDsa;

#[cortex_m_rt::exception]
unsafe fn HardFault(_frame: &cortex_m_rt::ExceptionFrame) -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}

/// Experimental selected ML-DSA backend; private diagnostics are optional and imply no certification.
pub struct TracingMlDsa44(SelectedMlDsa44);

impl Default for TracingMlDsa44 {
    fn default() -> Self {
        #[cfg(feature = "experimental-ml-dsa-rustcrypto")]
        return Self(SelectedMlDsa44::default());
        #[cfg(all(
            not(feature = "experimental-ml-dsa-rustcrypto"),
            feature = "chip-rp235xa"
        ))]
        return Self(manekey_rp::platform::rp2350::crypto::ml_dsa());
        #[cfg(all(
            not(feature = "experimental-ml-dsa-rustcrypto"),
            not(feature = "chip-rp235xa")
        ))]
        Self(manekey_rp::platform::rp::crypto::ml_dsa())
    }
}

impl manekey::ctaphid::credential_signature::CredentialSignatureBackend for TracingMlDsa44 {
    fn algorithm(&self) -> manekey::ctaphid::credential::CredentialAlgorithm {
        self.0.algorithm()
    }

    fn supports_current_build(&self) -> bool {
        self.0.supports_current_build()
    }

    fn create_key_material(
        &mut self,
        entropy: &mut dyn manekey::ctaphid::entropy::EntropySource,
    ) -> Result<
        [u8; manekey::ctaphid::credential_signature::CREDENTIAL_KEY_MATERIAL_LEN],
        manekey::ctaphid::credential_signature::CredentialSignatureError,
    > {
        self.0.create_key_material(entropy)
    }

    fn public_key<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], manekey::ctaphid::credential_signature::CredentialSignatureError> {
        let result = self.0.public_key(key_material, output);

        result
    }

    fn write_public_key_cose<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], manekey::ctaphid::credential_signature::CredentialSignatureError> {
        let result = self.0.write_public_key_cose(key_material, output);

        result
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8],
        message: &[&[u8]],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], manekey::ctaphid::credential_signature::CredentialSignatureError> {
        let result = self.0.sign(key_material, message, output);

        result
    }

    fn verify(
        &mut self,
        public_key: &[u8],
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), manekey::ctaphid::credential_signature::CredentialSignatureError> {
        self.0.verify(public_key, message, signature)
    }
}

/// Call exactly once before product setup or any selected-backend allocation.
pub fn initialize() {
    #[cfg(feature = "experimental-ml-dsa-rustcrypto")]
    {
        unsafe {
            embedded_alloc::init!(ML_DSA_HEAP, ML_DSA_HEAP_SIZE);
        }
    }
}
