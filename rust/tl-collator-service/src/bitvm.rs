//! BitVM procedural status (port of `src/bitvmStatus.ts`). The five referee artifacts
//! are supplied by the host through `Artifacts` (the host caches them and bounds the file
//! reads); this module only computes the status object. Field names, error strings and the
//! execution-context hash follow the TypeScript source line by line, including JavaScript
//! coercions (`jsval`).
use crate::jsval::{
    coalesce, get, lower, num, number_text, number_value, opt_string, or_chain, path, str_of,
    truthy, txid,
};
use serde_json::{json, Map, Value};
use tl_collator_wire::sha256_hex;

pub const ARTIFACT_FILES: [(&str, &str); 5] = [
    ("proceduralSync", "bitvm_procedural_sync_latest.json"),
    ("pipeline", "m1_pipeline_latest.json"),
    ("parallelUtxoIndex", "m1_parallel_utxo_index_latest.json"),
    ("challengeBundle", "m1_challenge_bundle_latest.json"),
    ("draft", "m1_dlc_draft_latest.json"),
];

#[derive(Clone, Debug, Default)]
pub struct Artifacts {
    pub procedural_sync: Option<Value>,
    pub pipeline: Option<Value>,
    pub parallel_utxo_index: Option<Value>,
    pub challenge_bundle: Option<Value>,
    pub draft: Option<Value>,
}

/// Host-side artifact loading. Implementations should cache; the reducer calls this at most
/// once per BitVM request and never from a message that was rate-limited away.
pub trait ArtifactSource {
    fn load(&mut self) -> Artifacts;
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BitvmQuery {
    pub property_id: Option<Value>,
    pub dlc_ref: Option<String>,
}

impl BitvmQuery {
    /// From an arbitrary request body. Only `propertyId` (number or short string) and
    /// `dlcRef` (short string) survive: the legacy handler echoed the whole body back.
    pub fn from_body(body: Option<&Value>) -> BitvmQuery {
        let property_id = get(body, "propertyId").and_then(|v| match v {
            Value::Number(_) => Some(v.clone()),
            Value::String(s) if s.len() <= 64 => Some(v.clone()),
            _ => None,
        });
        let dlc_ref = get(body, "dlcRef")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 256)
            .map(str::to_owned);
        BitvmQuery {
            property_id,
            dlc_ref,
        }
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        if let Some(p) = &self.property_id {
            m.insert("propertyId".into(), p.clone());
        }
        if let Some(d) = &self.dlc_ref {
            m.insert("dlcRef".into(), json!(d));
        }
        Value::Object(m)
    }
}

fn non_ready(reason: &str, query: &BitvmQuery, now_ms: u64) -> Value {
    json!({
        "source": "bitvmArtifacts",
        "featureEnabled": false,
        "commitScheme": "bitvm-dlc-procedural-receipt",
        "updatedAt": now_ms,
        "query": query.to_value(),
        "procedural": {
            "enabled": true,
            "ready": false,
            "executionContextReady": false,
            "contextWarnings": [],
            "contextErrors": [reason],
        },
    })
}

fn infer_chain_ticker(chain_id: Option<&str>) -> Option<&'static str> {
    let c = chain_id?;
    if c.contains("litecoin") {
        Some("LTC")
    } else if c.contains("bitcoin") {
        Some("BTC")
    } else {
        None
    }
}

fn find_funding_address(index: Option<&Value>) -> Option<String> {
    let txs = get(index, "transactions")?.as_array()?;
    let found = txs
        .iter()
        .flat_map(|item| match get(Some(item), "outputs") {
            Some(Value::Array(outs)) => outs.iter().collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .find(|o| get(Some(o), "role").and_then(Value::as_str) == Some("funding-output"));
    str_of(get(found, "address"))
}

fn find_selected_path_txid(index: Option<&Value>, selected: Option<&str>) -> Option<String> {
    let selected = selected?;
    let txs = get(index, "transactions")?.as_array()?;
    let record = txs
        .iter()
        .find(|item| str_of(get(Some(item), "txRole")).as_deref() == Some(selected));
    txid(get(record, "txid"))
}

fn artifact_summary(a: Option<&Value>) -> Value {
    if !truthy(a) {
        return Value::Null;
    }
    json!({
        "kind": opt_string(str_of(get(a, "kind"))),
        "createdAt": opt_string(str_of(get(a, "createdAt"))),
    })
}

fn js_json(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

/// `JSON.stringify` of the context object, keys in the source's insertion order.
#[allow(clippy::too_many_arguments)]
fn context_hash_payload(
    chain_id: Option<&str>,
    template_id: Option<&str>,
    contract_id: Option<&str>,
    funding_txid: Option<&str>,
    funding_vout: Option<f64>,
    selected_path_id: Option<&str>,
    selected_path_txid: Option<&str>,
    receipt_property_id: Option<f64>,
    settlement_route: Option<&str>,
) -> String {
    let s = |v: Option<&str>| js_json(v.unwrap_or(""));
    let vout = funding_vout
        .map(number_text)
        .unwrap_or_else(|| "\"\"".to_owned());
    let prop = match receipt_property_id {
        Some(f) if f != 0.0 => number_text(f),
        _ => "\"\"".to_owned(),
    };
    format!(
        "{{\"chainId\":{},\"templateId\":{},\"contractId\":{},\"fundingTxid\":{},\"fundingVout\":{},\"selectedPathId\":{},\"selectedPathTxid\":{},\"receiptPropertyId\":{},\"settlementRoute\":{}}}",
        s(chain_id),
        s(template_id),
        s(contract_id),
        s(funding_txid),
        vout,
        s(selected_path_id),
        s(selected_path_txid),
        prop,
        s(settlement_route),
    )
}

/// `collateral_property_id_env` is the raw `BITVM_COLLATERAL_PROPERTY_ID` (empty or unset
/// means 1); an unparsable value yields `null` like `Number("abc")` serialised by JSON.
pub fn build_status(
    artifacts: &Artifacts,
    query: &BitvmQuery,
    collateral_property_id_env: Option<&str>,
    now_ms: u64,
) -> Value {
    let ps = artifacts.procedural_sync.as_ref();
    if !truthy(ps) {
        return non_ready(&format!("Missing {}", ARTIFACT_FILES[0].1), query, now_ms);
    }
    let pipeline = artifacts.pipeline.as_ref();
    let pui = artifacts.parallel_utxo_index.as_ref();
    let bundle = artifacts.challenge_bundle.as_ref();
    let draft = artifacts.draft.as_ref();

    let requested = query.property_id.as_ref().and_then(|v| num(Some(v)));
    let receipt_property_id = num(get(ps, "propertyId"));
    if let (Some(r), Some(p)) = (requested, receipt_property_id) {
        if r != 0.0 && p != 0.0 && r != p {
            return non_ready(
                &format!(
                    "No BitVM procedural context for propertyId {}",
                    number_text(r)
                ),
                query,
                now_ms,
            );
        }
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let chain_id = lower(or_chain(&[
        path(ps, &["parallelUtxoIndex", "chainId"]),
        path(pui, &["chain", "chainId"]),
        path(draft, &["chain", "chainId"]),
    ]));
    let chain_ticker = infer_chain_ticker(chain_id.as_deref());
    let template_id = str_of(get(ps, "templateId"));
    let template_hash = lower(get(ps, "templateHash"));
    let draft_template_id = str_of(path(draft, &["template", "templateId"]));
    let draft_template_hash = lower(path(draft, &["template", "templateHash"]));
    let contract_id = str_of(get(ps, "contractId"));
    let funding_txid = txid(or_chain(&[
        get(ps, "fundingTxid"),
        path(ps, &["parallelUtxoIndex", "fundingTxid"]),
        path(pui, &["anchors", "fundingTxid"]),
        path(bundle, &["binding", "fundingTxidFinalized"]),
    ]));
    let funding_vout = num(coalesce(&[
        path(ps, &["funding", "fundingOutpoint", "vout"]),
        path(ps, &["fundingOutpoint", "vout"]),
        path(pui, &["anchors", "fundingOutpoint", "vout"]),
        path(bundle, &["binding", "fundingOutpoint", "vout"]),
    ]));
    let funded_amount_ltc = num(get(ps, "fundedAmountLtc"));
    let selected_path_id = str_of(or_chain(&[
        get(bundle, "selectedPathId"),
        path(bundle, &["selectedPath", "pathId"]),
        path(pipeline, &["options", "selectedPath"]),
        path(ps, &["settlement", "route"]),
    ]));
    let selected_path_txid = txid(path(bundle, &["selectedPath", "txid"]))
        .or_else(|| find_selected_path_txid(pui, selected_path_id.as_deref()));
    let route_value = path(ps, &["settlement", "route"]);
    let selected_value = selected_path_id.clone().map(Value::String);
    let settlement_route = str_of(or_chain(&[route_value, selected_value.as_ref()]));
    let settlement_kind = str_of(path(ps, &["settlement", "settlementKind"]));
    let funding_address = find_funding_address(pui);
    let operator_address = str_of(get(ps, "operatorAddress"));
    let funding_outpoint = match (&funding_txid, funding_vout) {
        (Some(t), Some(v)) => Some(format!("{t}:{}", number_text(v))),
        _ => None,
    };
    let context_id = match (&chain_id, &funding_outpoint, &selected_path_id) {
        (Some(c), Some(o), Some(p)) => Some(format!("{c}:{o}:{p}")),
        _ => None,
    };
    let context_hash = context_id.as_ref().map(|_| {
        sha256_hex(&context_hash_payload(
            chain_id.as_deref(),
            template_id.as_deref(),
            contract_id.as_deref(),
            funding_txid.as_deref(),
            funding_vout,
            selected_path_id.as_deref(),
            selected_path_txid.as_deref(),
            receipt_property_id,
            settlement_route.as_deref(),
        ))
    });

    if template_id.is_none() {
        errors.push("Missing templateId in procedural sync artifact.".into());
    }
    if contract_id.is_none() {
        errors.push("Missing contractId in procedural sync artifact.".into());
    }
    if funding_txid.is_none() {
        errors.push("Missing fundingTxid in referee artifacts.".into());
    }
    if funding_vout.is_none() {
        errors.push("Missing fundingVout in referee artifacts.".into());
    }
    if selected_path_id.is_none() {
        errors.push("Missing selectedPathId in referee artifacts.".into());
    }
    if selected_path_txid.is_none() {
        errors.push("Missing selectedPathTxid for the selected BitVM path.".into());
    }
    if funding_address.is_none() {
        errors.push("Missing funding output address in parallel UTXO index.".into());
    }
    if operator_address.is_none() {
        errors.push("Missing operatorAddress in procedural sync artifact.".into());
    }
    if let (Some(d), Some(t)) = (&draft_template_id, &template_id) {
        if d != t {
            errors.push(format!(
                "DLC draft templateId ({d}) does not match procedural sync templateId ({t})."
            ));
        }
    }
    if let (Some(d), Some(t)) = (&draft_template_hash, &template_hash) {
        if d != t {
            errors.push(format!(
                "DLC draft templateHash ({d}) does not match procedural sync templateHash ({t})."
            ));
        }
    }

    let step_status = match get(pipeline, "steps") {
        Some(Value::Array(steps)) => steps
            .iter()
            .find(|s| get(Some(s), "id").and_then(Value::as_str) == Some("settlementValidation"))
            .and_then(|s| get(Some(s), "status")),
        _ => None,
    };
    let settlement_validation = str_of(or_chain(&[
        path(pipeline, &["summary", "settlementValidation", "status"]),
        step_status,
    ]));
    if let Some(sv) = &settlement_validation {
        if sv != "ok" {
            warnings.push(format!(
                "Settlement validation is {sv}; artifact chain is not fully validated."
            ));
        }
    }

    let ready = errors.is_empty();
    let collateral = match collateral_property_id_env.filter(|s| !s.is_empty()) {
        None => Some(1.0),
        Some(s) => num(Some(&Value::String(s.to_owned()))),
    };
    let mut procedural = Map::new();
    let mut put = |k: &str, v: Value| {
        procedural.insert(k.to_owned(), v);
    };
    put("enabled", json!(true));
    put("ready", json!(ready));
    put("executionContextReady", json!(ready));
    put(
        "validationReady",
        json!(settlement_validation.as_deref() == Some("ok")),
    );
    put("replayOnly", json!(true));
    put("releaseReady", json!(false));
    put("chainId", opt_string(chain_id.clone()));
    put("chainTicker", opt_string(chain_ticker.map(str::to_owned)));
    put("state", opt_string(str_of(get(ps, "state"))));
    if let Some(p) = receipt_property_id.filter(|p| *p != 0.0) {
        put("receiptPropertyId", number_value(Some(p)));
    }
    put(
        "receiptTicker",
        opt_string(chain_ticker.map(|t| format!("r{t}-SAT"))),
    );
    put("collateralPropertyId", number_value(collateral));
    put("adminAddress", opt_string(operator_address.clone()));
    put("vaultAddress", opt_string(funding_address.clone()));
    put("fundingAddress", opt_string(funding_address.clone()));
    put("releaseSpendAddress", opt_string(operator_address.clone()));
    put(
        "holderAddress",
        opt_string(str_of(get(ps, "holderAddress"))),
    );
    put("operatorAddress", opt_string(operator_address));
    put(
        "oracleAddress",
        opt_string(str_of(get(ps, "oracleAddress"))),
    );
    put(
        "residualAddress",
        opt_string(str_of(get(ps, "residualAddress"))),
    );
    put("templateId", opt_string(template_id));
    put("templateHash", opt_string(template_hash));
    put("contractId", opt_string(contract_id));
    put("mintSettlementState", json!("FUNDED"));
    put("redeemSettlementState", json!("SETTLED"));
    put("fundingTxid", opt_string(funding_txid));
    put("fundingVout", number_value(funding_vout));
    put("fundingOutpoint", opt_string(funding_outpoint));
    put("fundedAmountLtc", number_value(funded_amount_ltc));
    put("settlementRoute", opt_string(settlement_route));
    put("settlementKind", opt_string(settlement_kind));
    put("selectedPathId", opt_string(selected_path_id));
    put("selectedPathTxid", opt_string(selected_path_txid));
    put("executionContextId", opt_string(context_id));
    put("executionContextHash", opt_string(context_hash));
    put("contextWarnings", json!(warnings));
    put("contextErrors", json!(errors));
    put(
        "sourceArtifacts",
        json!({
            "proceduralSync": artifact_summary(ps),
            "pipeline": artifact_summary(pipeline),
            "parallelUtxoIndex": artifact_summary(pui),
            "challengeBundle": artifact_summary(bundle),
            "draft": artifact_summary(draft),
        }),
    );

    json!({
        "source": "bitvmArtifacts",
        "featureEnabled": ready,
        "commitScheme": "bitvm-dlc-procedural-receipt",
        "updatedAt": now_ms,
        "query": query.to_value(),
        "procedural": Value::Object(procedural),
        "pipeline": {
            "status": opt_string(str_of(get(pipeline, "status"))),
            "mode": opt_string(str_of(path(pipeline, &["options", "mode"]))),
            "selectedPath": opt_string(str_of(path(pipeline, &["options", "selectedPath"]))),
            "settlementValidation": opt_string(settlement_validation),
        },
    })
}

impl<T: ArtifactSource + ?Sized> ArtifactSource for Box<T> {
    fn load(&mut self) -> Artifacts {
        (**self).load()
    }
}
