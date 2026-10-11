pub fn uses_ecall_island_policy() -> bool {
    cfg!(any(
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        any(),
        feature = "riscv-pmp-ble-mmio-runtime",
        feature = "riscv-pmp-usb-frontend"
    ))
}
