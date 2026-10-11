pub static PRESENCE_UI: manekey::user_interface::AtomicUiStatus =
    manekey::user_interface::AtomicUiStatus::new();
pub type PresenceObserver = manekey::user_interface::UiPresenceObserver<
    manekey::presence::NoPresenceObserver,
    &'static manekey::user_interface::AtomicUiStatus,
>;

/// Publish trusted presence hints; the asynchronous LED owner must consume the shared status.
pub fn presence_observer() -> PresenceObserver {
    manekey::user_interface::UiPresenceObserver::new(
        manekey::presence::NoPresenceObserver,
        &PRESENCE_UI,
    )
}
