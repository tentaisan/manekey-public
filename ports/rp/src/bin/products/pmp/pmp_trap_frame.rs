#[repr(C)]
/// C-layout register snapshot matching the assembly trap entry; monitor owns its storage exclusively.
pub struct TrapFrame {
    pub x: [u32; 32],
}
