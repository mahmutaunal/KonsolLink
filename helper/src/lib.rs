//! Privileged helper and bounded local protocol.
#[cfg(unix)]
mod dns_proxy;
#[cfg(unix)]
pub mod engine;
#[cfg(unix)]
pub mod gateway;
#[cfg(unix)]
pub mod interception;
#[cfg(unix)]
pub mod ipc;
#[cfg(unix)]
pub mod journal;
#[cfg(unix)]
pub mod runtime;

#[cfg(target_os = "macos")]
mod power;
