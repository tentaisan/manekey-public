// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(target_os = "linux"))]
compile_error!("manekey-linux-uhid requires Linux");

pub mod backend;
