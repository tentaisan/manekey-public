#[cfg(feature = "client-pin-flash")]
pub fn selected_product_string() -> &'static str {
    "ManeKey CH32V203 ClientPIN flash FIDO"
}

#[cfg(all(not(feature = "client-pin-flash"), feature = "client-pin-volatile"))]
pub fn selected_product_string() -> &'static str {
    "ManeKey CH32V203 ClientPIN volatile FIDO"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    feature = "flash-storage",
    feature = "dual-task"
))]
pub fn selected_product_string() -> &'static str {
    "ManeKey CH32V203 flash dual-task FIDO"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    feature = "flash-storage",
    not(feature = "dual-task")
))]
pub fn selected_product_string() -> &'static str {
    "ManeKey CH32V203 flash FIDO probe"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    not(feature = "flash-storage"),
    feature = "dual-task"
))]
pub fn selected_product_string() -> &'static str {
    "ManeKey CH32V203 volatile dual-task FIDO"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    not(feature = "flash-storage"),
    not(feature = "dual-task")
))]
pub fn selected_product_string() -> &'static str {
    "ManeKey CH32V203 volatile FIDO probe"
}

#[cfg(feature = "client-pin-flash")]
pub fn selected_serial_string() -> &'static str {
    "ch32v203-client-pin-flash"
}

#[cfg(all(not(feature = "client-pin-flash"), feature = "client-pin-volatile"))]
pub fn selected_serial_string() -> &'static str {
    "ch32v203-client-pin-volatile"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    feature = "flash-storage",
    feature = "dual-task"
))]
pub fn selected_serial_string() -> &'static str {
    "ch32v203-fido-flash-dual-task"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    feature = "flash-storage",
    not(feature = "dual-task")
))]
pub fn selected_serial_string() -> &'static str {
    "ch32v203-fido-flash"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    not(feature = "flash-storage"),
    feature = "dual-task"
))]
pub fn selected_serial_string() -> &'static str {
    "ch32v203-fido-volatile-dual-task"
}

#[cfg(all(
    not(any(feature = "client-pin-flash", feature = "client-pin-volatile")),
    not(feature = "flash-storage"),
    not(feature = "dual-task")
))]
pub fn selected_serial_string() -> &'static str {
    "ch32v203-fido-volatile"
}
