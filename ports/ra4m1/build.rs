fn main() {
    let nano = std::env::var_os("CARGO_FEATURE_BOARD_NANO_R4").is_some();
    let xiao = std::env::var_os("CARGO_FEATURE_BOARD_XIAO").is_some();
    assert!(nano != xiao, "select exactly one RA4M1 board feature");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let memory = if std::env::var_os("CARGO_FEATURE_MPU_INTERNAL").is_some() {
        let ccid = std::env::var_os("CARGO_FEATURE_MPU_USB_CCID").is_some();
        std::fs::copy(
            if ccid {
                "linker/mpu-sections-ccid.x"
            } else {
                "linker/mpu-sections.x"
            },
            out.join("mpu-sections.x"),
        )
        .unwrap();
        println!("cargo:rustc-link-arg-bin=ra4m1_mpu_internal=-Tmpu-sections.x");
        if ccid && nano {
            "linker/memory-nano-mpu-ccid.x"
        } else if ccid {
            "linker/memory-mpu-ccid.x"
        } else if nano {
            "linker/memory-nano-mpu.x"
        } else {
            "linker/memory-mpu.x"
        }
    } else {
        if nano {
            "linker/memory-nano.x"
        } else {
            "linker/memory.x"
        }
    };
    std::fs::copy(memory, out.join("memory.x")).unwrap();
    std::fs::write(out.join("device.x"), "INCLUDE ra-device.x\n").unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=linker/memory.x");
    println!("cargo:rerun-if-changed=linker/memory-mpu.x");
    println!("cargo:rerun-if-changed=linker/memory-nano.x");
    println!("cargo:rerun-if-changed=linker/memory-nano-mpu.x");
    println!("cargo:rerun-if-changed=linker/mpu-sections.x");
    println!("cargo:rerun-if-changed=linker/mpu-sections-ccid.x");
    println!("cargo:rerun-if-changed=linker/memory-mpu-ccid.x");
    println!("cargo:rerun-if-changed=linker/memory-nano-mpu-ccid.x");
    if std::env::var_os("CARGO_FEATURE_SCE5_RUNTIME").is_some() {
        let vendor = "vendor/renesas-sce5";
        let mut build = cc::Build::new();
        build
            .compiler("arm-none-eabi-gcc")
            .flag("-mcpu=cortex-m4")
            .flag("-mthumb")
            .flag("-mfpu=fpv4-sp-d16")
            .flag("-mfloat-abi=hard")
            .flag("-ffreestanding")
            .include("src/sce5")
            .include(vendor)
            .file("src/sce5/adapter.c");
        for name in [
            "p00", "p01", "p02", "p09", "subprc01", "subprc02", "func001", "func002", "func003",
        ] {
            build.file(format!("{vendor}/hw_sce_{name}.c"));
        }
        if std::env::var_os("CARGO_FEATURE_SCE5_AES").is_some() {
            for name in ["63", "64", "65", "85"] {
                build.file(format!("{vendor}/hw_sce_p{name}.c"));
            }
            build.file(format!("{vendor}/s_flash.c"));
            build.file(format!("{vendor}/hw_sce_func206.c"));
        }

        build.compile("manekey_ra_sce5");
        println!("cargo:rerun-if-changed=src/sce5");
        println!("cargo:rerun-if-changed={vendor}");
    }
}
