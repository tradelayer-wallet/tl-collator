//! Per-connection state (port of `src/peerSession.ts`). The WebSocket/data channel objects
//! stay with the host; the session keeps identity, limiter state and replay progress.
use crate::ratelimit::TokenBucket;
use tl_rpc_router::SessionId;

/// Opaque handle chosen by the host transport; never taken from a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostSession(pub u64);

#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub remote_ip: Option<String>,
    pub user_agent: Option<String>,
    pub asn: Option<u32>,
    pub vpn: Option<bool>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

pub struct PeerSession {
    pub id: HostSession,
    pub peer_id: String,
    pub meta: SessionMeta,
    /// True once the peer asked for the tape; with `replay_cursor == None` it also means the
    /// replay finished and live entries are pushed.
    pub wants_tape: bool,
    /// Next sequence number to send while a TAPE_SUB replay is in progress.
    pub replay_cursor: Option<u64>,
    pub channel_open: bool,
    pub router: Option<SessionId>,
    pub submit_bucket: TokenBucket,
    pub msg_bucket: TokenBucket,
    pub heavy_bucket: TokenBucket,
}

impl PeerSession {
    pub fn is_live(&self) -> bool {
        self.channel_open && self.wants_tape && self.replay_cursor.is_none()
    }
}
