//! Complete offline replay across individually bounded, authenticated exports.
use super::{
    checkpoint, deadline, fields, key, scope, text, uint, valid_challenge, verify_signature,
    visible, Config, FreshReceipt, RecoveryError, RecoveryExport, RecoveryLimits, Result,
    WitnessScope, MANIFEST_DOMAIN, MANIFEST_FIELDS,
};
use secp256k1::PublicKey;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use tl_collator_wire::{
    sha256_hex,
    verify::{Checkpoint, VerifiedReplay},
};

/// Aggregate limits, separate from per-response caps. A large history must not
/// become an unbounded series of otherwise valid small exports.
#[derive(Clone, Debug)]
pub struct RecoverySessionLimits {
    pub max_pages: usize,
    /// Includes all manifests, LF delimiters and signed NDJSON records.
    pub max_total_export_bytes: u64,
    pub timeout: Duration,
}
impl RecoverySessionLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_pages == 0
            || self.max_pages > 10_000
            || self.max_total_export_bytes == 0
            || self.max_total_export_bytes > 1024 * 1024 * 1024
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(24 * 60 * 60)
        {
            return Err(RecoveryError::Limit);
        }
        Ok(())
    }
}

/// No partial checkpoint is exposed. Any failed page permanently blocks this
/// verifier, including failures after some entries have been replayed. Finish
/// consumes the verifier and requires full genesis-to-target history plus a
/// fresh, independently challenge-bound receipt. This type never writes files.
pub struct PagedRecovery<'a> {
    config: &'a Config,
    witness_pubkey: String,
    witness_key: PublicKey,
    witness_scope: WitnessScope,
    operator_id: String,
    target: Checkpoint,
    page_limits: RecoveryLimits,
    session_limits: RecoverySessionLimits,
    replay: VerifiedReplay,
    challenges: BTreeSet<String>,
    pages: usize,
    bytes: u64,
    end: Instant,
    blocked: bool,
}
impl<'a> PagedRecovery<'a> {
    pub fn new(
        config: &'a Config,
        witness_pubkey: &str,
        operator_id: &str,
        target: Checkpoint,
        page_limits: RecoveryLimits,
        session_limits: RecoverySessionLimits,
    ) -> Result<Self> {
        config.validate().map_err(|_| RecoveryError::Invalid)?;
        page_limits.validate()?;
        session_limits.validate()?;
        if !visible(operator_id)
            || target.last_seq == 0
            || target.last_seq > config.max_entries as u64
            || target.seen_orders as u64 != target.last_seq
            || !lower_hash(&target.last_hash)
        {
            return Err(RecoveryError::Checkpoint);
        }
        let witness_key = key(witness_pubkey)?;
        let witness_scope = WitnessScope::new(
            &config.collator_id,
            &config.network,
            &config.stream,
            config.epoch,
            witness_pubkey,
        )
        .map_err(|_| RecoveryError::Invalid)?;
        witness_scope
            .assert_collator_identity(&config.collator_id, &config.collator_pubkey)
            .map_err(|_| RecoveryError::Invalid)?;
        let replay = VerifiedReplay::new(
            &config.collator_id,
            &config.collator_pubkey,
            config.max_entries,
        )
        .map_err(|_| RecoveryError::Invalid)?;
        let end = Instant::now()
            .checked_add(session_limits.timeout)
            .ok_or(RecoveryError::Limit)?;
        Ok(Self {
            config,
            witness_pubkey: witness_pubkey.into(),
            witness_key,
            witness_scope,
            operator_id: operator_id.into(),
            target,
            page_limits,
            session_limits,
            replay,
            challenges: BTreeSet::new(),
            pages: 0,
            bytes: 0,
            end,
            blocked: false,
        })
    }

    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// expected_challenge comes from the caller's independently authorized
    /// request, never from the response. Each page must use a new challenge.
    pub fn accept_page(&mut self, bundle: &RecoveryExport, expected_challenge: &str) -> Result<()> {
        if self.blocked {
            return Err(RecoveryError::Corrupt);
        }
        self.blocked = true;
        let result = self.accept_inner(bundle, expected_challenge);
        if result.is_ok() {
            self.blocked = false;
        }
        result
    }

    fn accept_inner(&mut self, bundle: &RecoveryExport, expected_challenge: &str) -> Result<()> {
        deadline(self.end)?;
        let page_end = Instant::now()
            .checked_add(self.page_limits.timeout)
            .ok_or(RecoveryError::Limit)?
            .min(self.end);
        if !valid_challenge(expected_challenge) || self.challenges.contains(expected_challenge) {
            return Err(RecoveryError::Freshness);
        }
        if self.pages >= self.session_limits.max_pages {
            return Err(RecoveryError::Limit);
        }
        let encoded = bundle
            .manifest
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(bundle.ndjson.len()))
            .ok_or(RecoveryError::Limit)?;
        let next_bytes = self
            .bytes
            .checked_add(encoded as u64)
            .ok_or(RecoveryError::Limit)?;
        if encoded > self.page_limits.max_export_bytes
            || next_bytes > self.session_limits.max_total_export_bytes
        {
            return Err(RecoveryError::Limit);
        }
        let manifest = fields(&bundle.manifest, MANIFEST_FIELDS)?;
        scope(&manifest, self.config)?;
        if text(&manifest, "domain")? != MANIFEST_DOMAIN
            || uint(&manifest, "v")? != 1
            || text(&manifest, "operatorId")? != self.operator_id
            || text(&manifest, "challenge")? != expected_challenge
            || text(&manifest, "witnessPubKey")? != self.witness_pubkey
            || text(&manifest, "collatorPubKey")? != self.config.collator_pubkey
        {
            return Err(RecoveryError::Unauthorized);
        }
        verify_signature(&manifest, "sigWitness", &self.witness_key)?;
        if checkpoint(&manifest)? != self.target {
            return Err(RecoveryError::Checkpoint);
        }
        let start = uint(&manifest, "startSeq")?;
        let count = uint(&manifest, "count")?;
        let finish = start
            .checked_add(count)
            .and_then(|n| n.checked_sub(1))
            .ok_or(RecoveryError::Limit)?;
        let before = self.replay.checkpoint();
        if count == 0
            || count > self.page_limits.max_records as u64
            || start != before.last_seq + 1
            || finish > self.target.last_seq
            || text(&manifest, "prevHash")? != before.last_hash
        {
            return Err(RecoveryError::Checkpoint);
        }
        if uint(&manifest, "bytes")? != bundle.ndjson.len() as u64
            || text(&manifest, "digest")? != sha256_hex(&bundle.ndjson)
            || !bundle.ndjson.ends_with('\n')
            || bundle.ndjson.contains('\r')
        {
            return Err(RecoveryError::Corrupt);
        }
        let mut actual = 0u64;
        for line in bundle.ndjson.split_terminator('\n') {
            deadline(page_end)?;
            actual = actual.checked_add(1).ok_or(RecoveryError::Limit)?;
            if actual > count || line.len() > self.page_limits.max_record_bytes {
                return Err(RecoveryError::Limit);
            }
            self.replay
                .apply_line(line)
                .map_err(|_| RecoveryError::Corrupt)?;
        }
        let after = self.replay.checkpoint();
        if actual != count
            || after.last_seq != finish
            || text(&manifest, "finalHash")? != after.last_hash
        {
            return Err(RecoveryError::Corrupt);
        }
        deadline(page_end)?;
        self.pages += 1;
        self.bytes = next_bytes;
        self.challenges.insert(expected_challenge.into());
        Ok(())
    }

    pub fn finish(self, fresh: FreshReceipt<'_>) -> Result<Checkpoint> {
        if self.blocked {
            return Err(RecoveryError::Corrupt);
        }
        deadline(self.end)?;
        validate_freshness(&fresh)?;
        if self.challenges.contains(fresh.challenge) {
            return Err(RecoveryError::Freshness);
        }
        if self.pages == 0 || self.replay.checkpoint() != self.target {
            return Err(RecoveryError::Checkpoint);
        }
        let receipt = self
            .witness_scope
            .verify_receipt(fresh.raw, fresh.challenge)
            .map_err(|_| RecoveryError::Freshness)?;
        if receipt.seq() != self.target.last_seq
            || receipt.head_hash() != self.target.last_hash
            || receipt.seen_orders() != self.target.seen_orders
        {
            return Err(RecoveryError::Checkpoint);
        }
        validate_freshness(&fresh)?;
        deadline(self.end)?;
        Ok(self.target)
    }
}

fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn validate_freshness(fresh: &FreshReceipt<'_>) -> Result<()> {
    if fresh.max_age.is_zero()
        || fresh.max_age > Duration::from_secs(30)
        || Instant::now()
            .checked_duration_since(fresh.requested_at)
            .is_none_or(|age| age > fresh.max_age)
    {
        return Err(RecoveryError::Freshness);
    }
    Ok(())
}
