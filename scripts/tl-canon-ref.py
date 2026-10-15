#!/usr/bin/env python3
"""Independent Python re-implementation of TL-Canon v1 (spec/schemas/tl-canon-v1.md).

Shares NO code with the TypeScript implementation. It exists so that the spec
*text* is executable and cross-checkable: any client (JS or not) that follows
the spec must derive byte-identical canonical JSON and orderIds. In particular
it pins the key ordering to ascending Unicode code point — NOT the
`JSON.stringify` object order (which emits integer-like keys numerically first)
and NOT UTF-16 code-unit order.

Usage:
  python3 scripts/tl-canon-ref.py [spec/test-vectors.json]   # verify all vectors (exit 1 on mismatch)
"""
import hashlib
import json
import sys

MAX_SAFE = 2**53 - 1


def esc(s: str) -> str:
    """JSON string escaping, byte-identical to JSON.stringify for these rules:
    short escapes for \\ " \\b \\f \\n \\r \\t, \\u00xx (lowercase hex) for other
    code points < 0x20, every other character emitted literally as UTF-8.
    Lone UTF-16 surrogates have no UTF-8 encoding and are rejected."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError("TL-Canon: string is not well-formed Unicode (lone surrogate U+%04X)" % cp)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(v) -> str:
    """TL-Canon v1 serialization:
    - objects: own keys sorted ascending by Unicode code point (prefix-first),
      keys with `undefined` values omitted (JSON input cannot express those),
      no whitespace;
    - arrays: order preserved;
    - numbers: safe integers only, serialized as decimal (integral floats such
      as 1.0 are their integer value);
    - strings: UTF-8, escaped as `esc`;
    - booleans/null: `true`/`false`/`null`."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int) and not isinstance(v, bool):
        if not -MAX_SAFE <= v <= MAX_SAFE:
            raise ValueError("TL-Canon: numbers must be safe integers, got %r" % v)
        return str(v)
    if isinstance(v, float):
        # JSON has one number type: a value that is an integer in the safe range
        # is that integer (1.0 == 1, as in JSON.parse). Anything else is rejected.
        if v.is_integer() and -MAX_SAFE <= v <= MAX_SAFE:
            return str(int(v))
        raise ValueError("TL-Canon: numbers must be safe integers, got %r" % v)
    if isinstance(v, str):
        return esc(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        parts = []
        for k in sorted(v.keys()):  # Python str sort == Unicode code point order
            val = v[k]
            parts.append(esc(k) + ":" + canon(val))
        return "{" + ",".join(parts) + "}"
    raise TypeError("TL-Canon: unsupported type %r" % type(v).__name__)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def envelope_order_id(envelope: dict) -> str:
    signed = {k: v for k, v in envelope.items() if k not in ("orderId", "sigTrader")}
    return sha256_hex(canon(signed))


def tape_entry_hash(entry: dict) -> str:
    material = {
        "v": entry["v"],
        "collatorId": entry["collatorId"],
        "seq": entry["seq"],
        "prevHash": entry["prevHash"],
        "receivedTs": entry["receivedTs"],
        "order": entry["order"],
    }
    return sha256_hex(canon(material))


def sig_payload_hash(entry: dict, entry_hash: str) -> str:
    return sha256_hex("%s|%s|%s|%s" % (entry["seq"], entry["prevHash"], entry["order"]["orderId"], entry_hash))


def main() -> int:
    vectors_path = sys.argv[1] if len(sys.argv) > 1 else "spec/test-vectors.json"
    vectors = json.load(open(vectors_path))
    failures = 0

    def check(label: str, got: str, want: str) -> None:
        nonlocal failures
        ok = got == want
        print("%-42s %s" % (label, "OK" if ok else "MISMATCH"))
        if not ok:
            print("  got:  %s\n  want: %s" % (got, want))
            failures += 1

    ot = vectors["orderTest"]
    check("orderTest.expectedOrderId", envelope_order_id(ot["envelopeNoSig"]), ot["expectedOrderId"])
    ct = vectors["orderCancelTest"]
    check("orderCancelTest.expectedOrderId", envelope_order_id(ct["envelopeNoSig"]), ct["expectedOrderId"])

    tt = vectors["tapeTest"]
    entry_hash = tape_entry_hash(tt["entryNoSig"])
    check("tapeTest.expectedEntryHash", entry_hash, tt["expectedEntryHash"])
    check("tapeTest.expectedSigPayloadHash", sig_payload_hash(tt["entryNoSig"], entry_hash), tt["expectedSigPayloadHash"])

    ik = vectors["integerKeyTest"]
    check("integerKeyTest.expectedCanonical", canon(ik["input"]), ik["expectedCanonical"])
    check("integerKeyTest.expectedSha256", sha256_hex(canon(ik["input"])), ik["expectedSha256"])
    oik = vectors["orderIntegerKeyTest"]
    check("orderIntegerKeyTest.expectedOrderId", envelope_order_id(oik["envelopeNoSig"]), oik["expectedOrderId"])
    uk = vectors["unicodeKeyOrderTest"]
    check("unicodeKeyOrderTest.expectedCanonical", canon(uk["input"]), uk["expectedCanonical"])
    check("unicodeKeyOrderTest.expectedSha256", sha256_hex(canon(uk["input"])), uk["expectedSha256"])

    nt = vectors["integralNumberTest"]
    check("integralNumberTest.expectedCanonical", canon(nt["input"]), nt["expectedCanonical"])

    # Inputs TL-Canon must refuse to serialize (fail closed, no hash produced).
    for case in vectors["rejectTests"]:
        try:
            canon(case["input"])
            accepted = True
        except (ValueError, TypeError):
            accepted = False
        print("%-42s %s" % ("reject: " + case["name"], "MISMATCH (accepted)" if accepted else "OK"))
        if accepted:
            failures += 1

    # Discriminating power: emulate the old `JSON.stringify`-based canonicalizer
    # (keys sorted lexicographically, then JSON.stringify hoists integer-like
    # keys numerically first) and prove it derives a DIFFERENT digest for the
    # integer-key envelope — that divergence is exactly what this vector pins
    # down. The emulation recurses so the only difference is key ordering.
    def json_stringify_key_order(d: dict):
        idx = [k for k in d if k.isdigit() and str(int(k)) == k and 0 <= int(k) < 2**32 - 1]
        rest = [k for k in d if k not in idx]
        return sorted(idx, key=int) + sorted(rest)

    def canon_json_stringify(v):
        if isinstance(v, list):
            return "[" + ",".join(canon_json_stringify(x) for x in v) + "]"
        if isinstance(v, dict):
            return "{" + ",".join(esc(k) + ":" + canon_json_stringify(v[k])
                                 for k in json_stringify_key_order(v)) + "}"
        return canon(v)

    js_style_hash = sha256_hex(canon_json_stringify(oik["envelopeNoSig"]))
    print("%-42s %s" % ("integer-key vector discriminates JSON.stringify order",
                        "OK" if js_style_hash != oik["expectedOrderId"] else "FAIL"))

    print("\n%s" % ("ALL TL-CANON VECTORS MATCH THE SPEC REFERENCE" if failures == 0 else "%d MISMATCH(ES)" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
