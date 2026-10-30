//! Parse sshd's SSH_ORIGINAL_COMMAND without evaluating a shell expression.
use tl_collator_wire::MAX_SAFE_INTEGER;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Witness,
    Recovery,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ForcedCommand {
    Latest {
        challenge: String,
    },
    Cas {
        seq: u64,
        hash: String,
        orders: u64,
        challenge: String,
    },
    Export,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

fn lower_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn challenge(s: &str) -> bool {
    lower_hash(s) && s.bytes().any(|b| b != b'0')
}
fn number(s: &str) -> Result<u64, Refused> {
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refused);
    }
    s.parse::<u64>()
        .ok()
        .filter(|n| *n <= MAX_SAFE_INTEGER)
        .ok_or(Refused)
}

/// Only the fixed grammar is accepted. `''` is the sole supported shell token
/// for the empty genesis hash. No quotes, escapes, substitutions, separators,
/// redirects, shell, subsystem or arbitrary program names are evaluated.
pub fn parse(capability: Capability, raw: &str) -> Result<ForcedCommand, Refused> {
    if raw.len() > 1024 || raw.bytes().any(|b| !b.is_ascii() || b.is_ascii_control()) {
        return Err(Refused);
    }
    let words: Vec<_> = raw.split(' ').filter(|s| !s.is_empty()).collect();
    match (capability, words.as_slice()) {
        (Capability::Recovery, ["witness-export"]) => Ok(ForcedCommand::Export),
        (Capability::Witness, ["witnessctl", "latest", nonce]) if challenge(nonce) => {
            Ok(ForcedCommand::Latest {
                challenge: (*nonce).into(),
            })
        }
        (Capability::Witness, ["witnessctl", "cas", seq, hash, orders, nonce])
            if challenge(nonce) =>
        {
            let seq = number(seq)?;
            let orders = number(orders)?;
            if seq != orders {
                return Err(Refused);
            }
            let hash = if seq == 0 && *hash == "''" {
                String::new()
            } else if seq > 0 && lower_hash(hash) {
                (*hash).into()
            } else {
                return Err(Refused);
            };
            Ok(ForcedCommand::Cas {
                seq,
                hash,
                orders,
                challenge: (*nonce).into(),
            })
        }
        _ => Err(Refused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roles_are_disjoint_and_genesis_hash_is_explicit() {
        let nonce = "ab".repeat(32);
        assert_eq!(
            parse(Capability::Recovery, "witness-export"),
            Ok(ForcedCommand::Export)
        );
        assert_eq!(parse(Capability::Witness, "witness-export"), Err(Refused));
        assert!(parse(Capability::Recovery, &format!("witnessctl latest {nonce}")).is_err());
        assert_eq!(
            parse(
                Capability::Witness,
                &format!("witnessctl cas 0 '' 0 {nonce}")
            ),
            Ok(ForcedCommand::Cas {
                seq: 0,
                hash: String::new(),
                orders: 0,
                challenge: nonce.clone()
            })
        );
        assert!(parse(Capability::Witness, &format!("witnessctl cas 0  0 {nonce}")).is_err());
        assert!(parse(
            Capability::Witness,
            &format!("witnessctl cas 1 {} 1 {nonce}", "aa".repeat(32))
        )
        .is_ok());
    }
    #[test]
    fn command_injection_subsystems_and_unbounded_values_are_refused() {
        let nonce = "ab".repeat(32);
        for raw in [
            String::new(),
            "sh".into(),
            "sftp".into(),
            "witness-export extra".into(),
            format!("witnessctl latest {nonce}; true"),
            format!("witnessctl latest {nonce}\ntrue"),
            format!("witnessctl latest '{nonce}'"),
            format!("witnessctl latest $(printf {nonce})"),
            format!("witnessctl cas 0 '' 1 {nonce}"),
            format!("witnessctl cas 1 '' 1 {nonce}"),
            format!("witnessctl cas -1 '' 0 {nonce}"),
            format!("witnessctl latest {}", "0".repeat(64)),
            format!(
                "witnessctl cas 9007199254740992 {} 9007199254740992 {nonce}",
                "ab".repeat(32)
            ),
            "x".repeat(1025),
        ] {
            assert!(parse(Capability::Witness, &raw).is_err(), "{raw:?}");
            assert!(parse(Capability::Recovery, &raw).is_err(), "{raw:?}");
        }
    }
}
