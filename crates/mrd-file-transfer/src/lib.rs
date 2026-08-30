//! Authenticated, bounded remote file-transfer primitives.
//!
//! The crate intentionally contains no local-copy fallback.  A caller must
//! select [`protocol::TransferProvider::Remote`] and provide a session-bound
//! file-bulk transport; unsupported providers are represented as errors.

#![warn(missing_docs)]

/// Bounded chunk construction and digest verification.
pub mod chunking;
/// Transfer-root and relative-path validation.
pub mod paths;
/// Authenticated file-transfer wire contracts and limits.
pub mod protocol;
/// Contiguous resume-state validation and final digest checks.
pub mod resume;

pub use protocol::{FileBulkMessage, FileDirection, FileTransferManifest, TransferProvider};
