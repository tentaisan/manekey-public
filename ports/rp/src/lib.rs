#![no_std]

#[cfg(all(
    feature = "rp2350-ml-dsa-credential-experimental",
    not(feature = "experimental-large-message-buffers")
))]
compile_error!("RP2350 ML-DSA credentials require port-side large message buffers");

pub mod platform {
    #[cfg(any(
        all(
            target_arch = "arm",
            target_os = "none",
            any(
                feature = "chip-rp2040",
                feature = "chip-rp235xa",
                feature = "chip-rp235xa-nonsecure"
            )
        ),
        all(
            target_arch = "riscv32",
            target_os = "none",
            feature = "riscv-rp2350-hal"
        )
    ))]
    pub mod rp {
        pub mod crypto;
        pub mod flash_layout;
        pub mod key_store;
        #[cfg(all(
            target_arch = "arm",
            target_os = "none",
            feature = "rp-flash-managed-keys"
        ))]
        pub mod managed_flash;
        pub(crate) const PIN_STORAGE_PAGE_COUNT: usize = 2;

        pub mod entropy;
        #[cfg(all(target_arch = "arm", target_os = "none"))]
        pub mod mailbox;
        pub mod storage;
        pub mod storage_mailbox;
        pub mod user_interface;
    }

    #[cfg(any(
        test,
        all(
            target_arch = "arm",
            target_os = "none",
            any(feature = "chip-rp235xa", feature = "chip-rp235xa-nonsecure")
        ),
        all(
            target_arch = "riscv32",
            target_os = "none",
            any(feature = "riscv-rp2350-hal", feature = "riscv-pmp-ble-user-image")
        )
    ))]
    pub mod rp2350 {
        #[cfg(all(
            target_arch = "arm",
            target_os = "none",
            feature = "rp2350-cyw43-polling",
            feature = "cyw43-ble"
        ))]
        pub mod arm_cyw43_polling;
        #[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp235xa"))]
        pub mod arm_security;
        #[cfg(all(not(test), not(feature = "riscv-pmp-ble-user-image")))]
        pub mod crypto;
        pub mod cyw43_polling;
        pub mod entropy;
        pub mod flash_layout;
        #[cfg(all(
            any(
                feature = "riscv-flash-managed-keys",
                feature = "rp2350-flash-managed-keys"
            ),
            target_os = "none"
        ))]
        pub mod key_store;
        #[cfg(all(
            feature = "rp2350-flash-managed-keys",
            target_arch = "arm",
            target_os = "none"
        ))]
        pub mod managed_flash;
        #[cfg(all(feature = "rp-internal-uart", feature = "trustzone-nonsecure-image"))]
        pub mod nonsecure_uart;
        pub mod pmp;
        #[cfg(any(
            test,
            all(
                target_arch = "riscv32",
                target_os = "none",
                any(
                    feature = "riscv-pmp-ble-mmio-runtime",
                    feature = "riscv-pmp-ble-user-image"
                )
            )
        ))]
        pub mod pmp_cyw43_gpio;
        pub mod pmp_cyw43_pio_abi;
        #[cfg(any(
            test,
            all(
                target_arch = "riscv32",
                target_os = "none",
                any(
                    feature = "riscv-pmp-ble-monitor-dma-policy",
                    any(),
                    any(),
                    feature = "riscv-pmp-ble-user-dma-backend"
                )
            )
        ))]
        pub mod pmp_dma;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            any(
                feature = "riscv-rp2350-hal",
                feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental"
            )
        ))]
        pub mod pmp_usb;
        #[cfg(any(
            test,
            all(
                target_arch = "riscv32",
                target_os = "none",
                feature = "riscv-pmp-ble-mmio-runtime"
            )
        ))]
        pub mod pmp_user_executor;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            feature = "riscv-rp2350-hal"
        ))]
        pub mod riscv_crypto;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            any(
                feature = "riscv-cyw43-backend-experimental",
                feature = "riscv-pmp-ble-user-image"
            )
        ))]
        pub mod riscv_cyw43_pio;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            feature = "riscv-rp2350-hal"
        ))]
        pub mod riscv_dual_core;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            feature = "riscv-embassy-time-experimental"
        ))]
        pub mod riscv_embassy_time;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            feature = "riscv-rp2350-hal"
        ))]
        pub mod riscv_token_clock;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            feature = "riscv-rp2350-hal"
        ))]
        pub mod riscv_ui;
        #[cfg(all(
            target_arch = "riscv32",
            target_os = "none",
            any(
                feature = "riscv-rp2350-hal",
                feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental"
            )
        ))]
        pub mod riscv_usb;
        pub mod sha256;
    }
}
