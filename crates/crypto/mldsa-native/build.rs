// SPDX-License-Identifier: Apache-2.0
fn main() {
    println!("cargo:rerun-if-changed=upstream/mldsa_native.c");
    println!("cargo:rerun-if-changed=upstream/mldsa_native.h");
    println!("cargo:rerun-if-changed=upstream/mldsa_native_config.h");
    println!("cargo:rerun-if-changed=src/bridge.c");
    println!("cargo:rerun-if-changed=freestanding/include/string.h");

    let mut build = cc::Build::new();
    build
        .include("upstream")
        .file("upstream/mldsa_native.c")
        .file("src/bridge.c")
        .define("MLD_CONFIG_PARAMETER_SET", "44")
        .define("MLD_CONFIG_NAMESPACE_PREFIX", "manekey_mldsa")
        .define("MLD_CONFIG_REDUCE_RAM", None)
        .define("MLD_CONFIG_CORE_API_ONLY", None)
        .define("MLD_CONFIG_NO_RANDOMIZED_API", None)
        .flag_if_supported("-std=c99")
        .warnings_into_errors(true);

    let riscv_march = match std::env::var("TARGET").as_deref() {
        Ok("riscv32imc-unknown-none-elf") => Some("rv32imc"),
        Ok("riscv32imac-unknown-none-elf") => Some("rv32imac"),
        _ => None,
    };
    if let Some(march) = riscv_march {
        build
            .compiler("clang")
            .include("freestanding/include")
            .flag(format!("-march={march}"))
            .flag("-mabi=ilp32")
            .flag("-ffreestanding");
    }
    if let Ok(target) = std::env::var("TARGET") {
        let compiler = match target.as_str() {
            "xtensa-esp32-none-elf" => Some("xtensa-esp32-elf-gcc"),
            "xtensa-esp32s2-none-elf" => Some("xtensa-esp32s2-elf-gcc"),
            "xtensa-esp32s3-none-elf" => Some("xtensa-esp32s3-elf-gcc"),
            _ => None,
        };
        if let Some(compiler) = compiler {
            build
                .compiler(compiler)
                .flag("-mlongcalls")
                .flag("-ffreestanding");
        }
    }

    build.compile("manekey_mldsa_native");
}
