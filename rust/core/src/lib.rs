//! wina-core: Rust reimplementation of the Windows-Analysis parsing pipeline.
//! Produces SQLite output schema-compatible with the Python pipeline so the
//! existing viewer keeps working while parsers are migrated one by one.
pub mod case_store;
pub mod finder;
pub mod overview;
pub mod parsers;
pub mod pipeline;
pub mod sqlite;
pub mod time;
