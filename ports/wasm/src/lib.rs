// SPDX-License-Identifier: AGPL-3.0-only
#![no_std]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("manekey-wasm requires wasm32");

pub mod backend;
mod runtime;
