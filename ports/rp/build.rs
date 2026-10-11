use std::{env, fs, path::PathBuf};

mod build_inputs;

fn main() {
    build_inputs::configure_nvram();
    if env::var_os("CARGO_FEATURE_RP_FLASH_MANAGED_KEYS").is_some()
        && (env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("arm")
            || env::var_os("CARGO_FEATURE_TRUSTZONE_NONSECURE_IMAGE").is_some()
            || (env::var_os("CARGO_FEATURE_CHIP_RP2040").is_none()
                && env::var_os("CARGO_FEATURE_CHIP_RP235XA").is_none()))
    {
        panic!("Arm managed media requires a trusted RP owner");
    }
    if env::var_os("CARGO_FEATURE_RP2350_FLASH_MANAGED_KEYS").is_some()
        && (env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("arm")
            || env::var_os("CARGO_FEATURE_CHIP_RP235XA").is_none()
            || env::var_os("CARGO_FEATURE_TRUSTZONE_NONSECURE_IMAGE").is_some())
    {
        panic!("Arm managed keys require the RP2350 trusted owner, never a Non-secure image");
    }
    if env::var_os("CARGO_FEATURE_RISCV_FLASH_MANAGED_KEYS").is_some() {
        if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("riscv32")
            || env::var_os("CARGO_FEATURE_RISCV_PMP_BLE_USER_IMAGE").is_some()
        {
            panic!("RISC-V managed media belongs to the RP2350 trusted owner, not Arm or U image");
        }

        println!("cargo:rustc-link-arg=--defsym=__riscv_storage_start=0x103f9000");
        println!("cargo:rustc-link-arg=--defsym=__riscv_min_main_stack=65536");
    }
    if env::var_os("CARGO_FEATURE_RISCV_PMP_USB_INTERNAL_CCID").is_some() {
        println!("cargo:rustc-link-arg=--defsym=__pmp_user_stack_alignment=65536");
    }
    println!("cargo:rustc-check-cfg=cfg(has_fpu)");

    let arm_rp2040_image = env::var_os("CARGO_FEATURE_CHIP_RP2040").is_some();
    let arm_rp2350_image = env::var_os("CARGO_FEATURE_CHIP_RP235XA").is_some();
    let arm_rp2350_nonsecure = env::var_os("CARGO_FEATURE_CHIP_RP235XA_NONSECURE").is_some();
    let arm_rp2350_multicore = env::var_os("CARGO_FEATURE_DUAL_CORE_RP2350").is_some();
    let secure_layout = env::var_os("CARGO_FEATURE_TRUSTZONE_SECURE_LAYOUT").is_some();
    let nonsecure_layout = env::var_os("CARGO_FEATURE_TRUSTZONE_NONSECURE_IMAGE").is_some();
    let trustzone_usb_ble_nonsecure =
        env::var_os("CARGO_FEATURE_TRUSTZONE_USB_BLE_NONSECURE_EXPERIMENTAL").is_some();
    let pmp_ble_monitor_layout = env::var_os("CARGO_FEATURE_RISCV_PMP_BLE_MONITOR_IMAGE").is_some();
    let pmp_ble_monitor_ml_dsa_layout =
        env::var_os("CARGO_FEATURE_RISCV_PMP_BLE_MONITOR_ML_DSA_LAYOUT").is_some();
    let pmp_ble_user_layout = env::var_os("CARGO_FEATURE_RISCV_PMP_BLE_USER_IMAGE").is_some();
    let pmp_monolithic_large_message_layout =
        env::var_os("CARGO_FEATURE_RISCV_PMP_MONOLITHIC_LARGE_MESSAGE_LAYOUT").is_some();
    let riscv_image = env::var_os("CARGO_FEATURE_RISCV_EMBASSY_TIME_EXPERIMENTAL").is_some()
        || env::var_os("CARGO_FEATURE_RISCV_PICO_2_W_BLE_RUNTIME").is_some()
        || env::var_os("CARGO_FEATURE_RISCV_SINGLE_CORE").is_some()
        || env::var_os("CARGO_FEATURE_RISCV_DUAL_CORE_RUNTIME").is_some()
        || env::var_os("CARGO_FEATURE_RISCV_PMP_RUNTIME").is_some();

    if [
        secure_layout,
        nonsecure_layout,
        pmp_ble_monitor_layout,
        pmp_ble_user_layout,
        pmp_monolithic_large_message_layout,
    ]
    .into_iter()
    .filter(|selected| *selected)
    .count()
        > 1
    {
        panic!("select only one split-image linker layout");
    }

    let memory_file = if pmp_ble_user_layout {
        "../rp2350/linker/riscv/pmp-ble-user.x"
    } else if pmp_ble_monitor_ml_dsa_layout {
        "../rp2350/linker/riscv/pmp-ble-monitor-ml-dsa.x"
    } else if pmp_ble_monitor_layout {
        "../rp2350/linker/riscv/pmp-ble-monitor.x"
    } else if pmp_monolithic_large_message_layout {
        "../rp2350/linker/riscv/pmp-monolithic-large-message.x"
    } else if nonsecure_layout {
        if !arm_rp2350_nonsecure {
            panic!("trustzone-nonsecure-image requires chip-rp235xa-nonsecure");
        }
        "../rp2350/linker/trustzone/nonsecure.x"
    } else if secure_layout {
        if !arm_rp2350_image {
            panic!("trustzone-secure-layout requires chip-rp235xa");
        }
        "../rp2350/linker/trustzone/secure.x"
    } else if arm_rp2350_multicore {
        "../rp2350/linker/arm/multicore.x"
    } else if arm_rp2040_image {
        "../rp2040/linker/memory.x"
    } else if arm_rp2350_image {
        "../rp2350/linker/arm/default.x"
    } else if riscv_image {
        "../rp2350/linker/riscv/runtime-pmp.x"
    } else {
        return;
    };

    let memory_file = if env::var_os("CARGO_FEATURE_RP2350_MANAGED_FLASH_LAYOUT").is_some() {
        match memory_file {
            "../rp2350/linker/arm/default.x" => "../rp2350/linker/arm/default-managed.x",
            "../rp2350/linker/arm/multicore.x" => "../rp2350/linker/arm/multicore-managed.x",
            "../rp2350/linker/trustzone/nonsecure.x" => {
                "../rp2350/linker/trustzone/nonsecure-managed.x"
            }
            other => other,
        }
    } else {
        memory_file
    };
    let memory_file =
        if arm_rp2040_image && env::var_os("CARGO_FEATURE_RP_FLASH_MANAGED_KEYS").is_some() {
            if env::var_os("CARGO_FEATURE_RP2040_MPU_PRODUCT").is_some() {
                "../rp2040/linker/memory-managed-mpu.x"
            } else {
                "../rp2040/linker/memory-managed.x"
            }
        } else {
            memory_file
        };
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    if env::var_os("CARGO_FEATURE_RP2040_MPU_PRODUCT").is_some() {
        let check = "../rp2040/linker/mpu-product-check.x";
        fs::copy(check, out.join("mpu-product-check.x")).expect("copy RP2040 MPU link checks");
        let min_stack = if env::var_os("CARGO_FEATURE_EXPERIMENTAL_LARGE_MESSAGE_BUFFERS").is_some()
        {
            65536
        } else {
            16384
        };
        println!(
            "cargo:rustc-link-arg-bin=rp2040-mpu-internal=--defsym=__mpu_min_stack={min_stack}"
        );
        println!("cargo:rustc-link-arg-bin=rp2040-mpu-internal=-Tmpu-product-check.x");
        println!("cargo:rerun-if-changed={check}");
    }
    fs::copy(memory_file, out.join("memory.x")).expect("copy RP2350 RISC-V memory layout");
    if pmp_ble_monitor_layout || pmp_monolithic_large_message_layout {
        let runtime = "../rp2350/linker/riscv/runtime-pmp.x";
        fs::copy(runtime, out.join("runtime-pmp.x")).expect("copy shared RISC-V runtime layout");
        println!("cargo:rerun-if-changed={runtime}");
    }
    println!("cargo:rustc-link-search={}", out.display());
    if trustzone_usb_ble_nonsecure {
        println!("cargo:rustc-link-arg-bin=tz-nonsecure-usb-ble=--wrap=__pre_init");
    }
    if env::var_os("CARGO_FEATURE_TRUSTZONE_MULTI_INGRESS_NONSECURE").is_some() {
        println!("cargo:rustc-link-arg-bin=tz-nonsecure-multi-transport=--wrap=__pre_init");
    }
    println!("cargo:rerun-if-changed={memory_file}");
}
