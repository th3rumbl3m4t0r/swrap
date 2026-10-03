//! swrec v1.2: recording and log file format (spec section 8).

pub mod ai;
pub mod compress;
pub mod format;
pub mod osc;
pub mod reader;
pub mod render;
pub mod repeat;
pub mod search;
pub mod text;
pub mod writer;

pub use format::{RecSigner, RecVerifier};
pub use reader::{scan, ScanOpts, Status};
pub use writer::{Writer, WriterOpts};
