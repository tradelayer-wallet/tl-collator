//! The few JavaScript value semantics `src/bitvmStatus.ts` relies on (`?.`, `??`, `||`,
//! `String(x)`, `Number(x)`), over `Option<&Value>` where `None` is `undefined` and
//! `Some(Value::Null)` is `null`. Used only by the BitVM status port, so a fixture
//! produces the same fields the TypeScript produced.
use serde_json::{Number, Value};

/// `v?.key`
pub fn get<'a>(v: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    match v? {
        Value::Object(m) => m.get(key),
        _ => None,
    }
}

/// `v?.a?.b?.c`
pub fn path<'a>(v: Option<&'a Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().fold(v, |acc, k| get(acc, k))
}

fn nullish(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null))
}

/// JavaScript truthiness.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `a ?? b ?? c`: the first non-nullish operand, else the last operand (which may be null).
pub fn coalesce<'a>(candidates: &[Option<&'a Value>]) -> Option<&'a Value> {
    for c in candidates {
        if !nullish(*c) {
            return *c;
        }
    }
    candidates.last().copied().flatten()
}

/// `a || b || c`: the first truthy operand, else the last operand.
pub fn or_chain<'a>(candidates: &[Option<&'a Value>]) -> Option<&'a Value> {
    for c in candidates {
        if truthy(*c) {
            return *c;
        }
    }
    candidates.last().copied().flatten()
}

/// JavaScript number formatting for the values that appear here (integral values print
/// without a fraction; very large or tiny magnitudes use Rust's formatting, a documented gap).
pub fn number_text(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{f:.0}")
    } else {
        format!("{f}")
    }
}

/// `String(v)` for a defined, non-null value.
fn js_string_defined(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.as_f64().map(number_text).unwrap_or_else(|| n.to_string()),
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .map(|e| {
                if nullish(Some(e)) {
                    String::new()
                } else {
                    js_string_defined(e)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

/// `String(v ?? '').trim()` returning `None` for the empty string (`str()` in the source).
pub fn str_of(v: Option<&Value>) -> Option<String> {
    if nullish(v) {
        return None;
    }
    let text = js_string_defined(v?);
    let t = text.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

pub fn lower(v: Option<&Value>) -> Option<String> {
    str_of(v).map(|s| s.to_lowercase())
}

/// 64 lowercase hex characters after trimming and lowercasing.
pub fn txid(v: Option<&Value>) -> Option<String> {
    lower(v).filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn parse_js_number(text: &str) -> Option<f64> {
    let t = text.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0b", 2),
        ("0B", 2),
        ("0o", 8),
        ("0O", 8),
    ] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return u64::from_str_radix(rest, radix).ok().map(|n| n as f64);
        }
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b))
    {
        return None;
    }
    t.parse::<f64>().ok()
}

/// `Number(v)`; `None` is NaN. `Number(null)` is 0 and `Number(undefined)` is NaN.
pub fn number_of(v: Option<&Value>) -> Option<f64> {
    let f = match v {
        None => return None,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64()?,
        Some(Value::String(s)) => parse_js_number(s)?,
        Some(Value::Array(a)) if a.is_empty() => 0.0,
        Some(Value::Array(a)) if a.len() == 1 => parse_js_number(&js_string_defined(&a[0]))?,
        Some(_) => return None,
    };
    f.is_finite().then_some(f)
}

/// `num()` in the source: `Number(v)` when finite, else `null`.
pub fn num(v: Option<&Value>) -> Option<f64> {
    number_of(v)
}

pub fn number_value(f: Option<f64>) -> Value {
    match f {
        Some(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => Value::Number(Number::from(n as i64)),
        Some(n) => Number::from_f64(n)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        None => Value::Null,
    }
}

pub fn opt_string(s: Option<String>) -> Value {
    s.map(Value::String).unwrap_or(Value::Null)
}
