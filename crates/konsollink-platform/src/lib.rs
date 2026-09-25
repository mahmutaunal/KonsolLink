use konsollink_core::{ConsoleDevice, ServiceProfile};
use thiserror::Error;

pub mod deployment;
pub mod observer;
pub mod preflight;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("unsupported platform")]
    Unsupported,
    #[error("operation failed: {0}")]
    Operation(String),
}

pub trait NetworkBackend: Send {
    /// Capture enough pre-change state to guarantee deterministic rollback.
    fn snapshot(&mut self) -> Result<(), PlatformError>;
    /// Configure forwarding/gateway only for the selected console.
    fn enable_gateway(&mut self, console: &ConsoleDevice) -> Result<(), PlatformError>;
    /// Intercept only traffic selected by the Discord service profile.
    fn enable_service_bypass(&mut self, profile: &ServiceProfile) -> Result<(), PlatformError>;
    /// Remove temporary rules and restore the captured network state.
    fn restore(&mut self) -> Result<(), PlatformError>;
    fn healthcheck(&self) -> Result<(), PlatformError>;
}

pub struct DryRunBackend {
    snapshotted: bool,
    active: bool,
}

impl DryRunBackend {
    pub fn new() -> Self {
        Self {
            snapshotted: false,
            active: false,
        }
    }
}

impl Default for DryRunBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBackend for DryRunBackend {
    fn snapshot(&mut self) -> Result<(), PlatformError> {
        self.snapshotted = true;
        Ok(())
    }
    fn enable_gateway(&mut self, _: &ConsoleDevice) -> Result<(), PlatformError> {
        if !self.snapshotted {
            return Err(PlatformError::Operation("snapshot required".into()));
        }
        self.active = true;
        Ok(())
    }
    fn enable_service_bypass(&mut self, _: &ServiceProfile) -> Result<(), PlatformError> {
        if !self.active {
            return Err(PlatformError::Operation("gateway required".into()));
        }
        Ok(())
    }
    fn restore(&mut self) -> Result<(), PlatformError> {
        self.active = false;
        Ok(())
    }
    fn healthcheck(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
