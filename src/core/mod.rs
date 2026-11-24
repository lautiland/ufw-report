pub mod cache;
pub mod hash;
pub mod inputs;
pub mod parser;
pub mod range;

pub use inputs::{resolve_inputs, InputFile, DEFAULT_MAX_DECOMPRESSED_BYTES};
pub use range::{
    parse_logs_with_options, parse_ufw_log_range, parse_ufw_log_range_with_options, ParseOptions,
    ParseResult,
};
