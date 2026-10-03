//! swrap-core: shared foundation for all swrap binaries.

pub mod api;
pub mod atomic;
pub mod config;
pub mod frame;
pub mod git;
pub mod net;
pub mod paths;
pub mod rbac;
pub mod sys;
pub mod time;

pub use paths::Paths;

/// New sortable id (ULID, Crockford base32).
pub fn new_id() -> String {
    ulid::Ulid::new().to_string()
}
