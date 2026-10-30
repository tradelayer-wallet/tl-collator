//! Audit log record format (port of `src/auditLog.ts` and the record built at
//! `src/index.ts` 1211-1221). The record is one JSON object per line, keys in the
//! legacy insertion order: `ts, collatorId, peerId, ip, asn, vpn, orderId, traderPubKey, seq`
//! (absent optionals are omitted, as `JSON.stringify` omits `undefined`).
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub ts: u64,
    pub collator_id: String,
    pub peer_id: String,
    pub ip: Option<String>,
    pub asn: Option<u32>,
    pub vpn: Option<bool>,
    pub order_id: String,
    pub trader_pub_key: String,
    pub seq: u64,
}

fn js(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}

impl AuditRecord {
    /// One line without the trailing newline.
    pub fn to_line(&self) -> String {
        let mut parts = vec![
            format!("\"ts\":{}", self.ts),
            format!("\"collatorId\":{}", js(&self.collator_id)),
            format!("\"peerId\":{}", js(&self.peer_id)),
        ];
        if let Some(ip) = &self.ip {
            parts.push(format!("\"ip\":{}", js(ip)));
        }
        if let Some(asn) = self.asn {
            parts.push(format!("\"asn\":{asn}"));
        }
        if let Some(vpn) = self.vpn {
            parts.push(format!("\"vpn\":{vpn}"));
        }
        parts.push(format!("\"orderId\":{}", js(&self.order_id)));
        parts.push(format!("\"traderPubKey\":{}", js(&self.trader_pub_key)));
        parts.push(format!("\"seq\":{}", self.seq));
        format!("{{{}}}", parts.join(","))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditError;

pub trait AuditSink {
    /// Append one line. The service counts failures instead of dropping them silently.
    fn write(&mut self, line: &str) -> Result<(), AuditError>;
}

/// In-memory sink for tests and embedding; bounded by `max_lines` (oldest dropped).
#[derive(Default)]
pub struct MemoryAudit {
    pub lines: Vec<String>,
    pub max_lines: usize,
}

impl MemoryAudit {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: Vec::new(),
            max_lines: max_lines.max(1),
        }
    }
}

impl AuditSink for MemoryAudit {
    fn write(&mut self, line: &str) -> Result<(), AuditError> {
        if self.lines.len() >= self.max_lines {
            self.lines.remove(0);
        }
        self.lines.push(line.to_owned());
        Ok(())
    }
}
