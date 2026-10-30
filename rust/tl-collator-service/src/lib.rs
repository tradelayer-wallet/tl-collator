//! Offline pure-reducer port of the tl-collator service layer.
//!
//! No socket, timer, file, key or clock is owned here. The host supplies session ids, text
//! frames, parsed HTTP requests and `now_ms`; it performs the `Out` values returned. The
//! cryptographic and ledger rules live in `tl-collator-wire`, provider routing in
//! `tl-rpc-router`; this crate adds configuration, limits, admission policy and the
//! `WireMsg`/HTTP dispatcher on top of them.
#![forbid(unsafe_code)]

pub mod audit;
pub mod bitvm;
pub mod clearlist;
pub mod config;
pub mod http;
pub mod ipintel;
pub mod jsval;
pub mod lru;
pub mod manifest;
pub mod order;
pub mod peer;
pub mod ratelimit;
pub mod service;
pub mod signer;
pub mod tape;
pub mod wire;

pub use peer::HostSession;
pub use service::{Out, Service, ServiceParts};
