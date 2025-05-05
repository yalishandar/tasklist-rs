//! Platform-specific implementation for Windows
//!
//! Contains Windows-specific types and functionality implementations

pub mod handle;
pub use handle::{ProcessHandle, SnapshotHandle, TokenHandle};

#[cfg(test)]
mod tests {
    // Windows platform specific tests
}