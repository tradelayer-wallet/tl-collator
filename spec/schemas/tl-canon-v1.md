# TL-Canon v1

Deterministic canonical JSON used for hashing/signing.

Rules:
- Objects: recursively sort keys lexicographically (`Object.keys().sort()` order).
- No whitespace: canonical JSON has no spaces/newlines.
- Arrays: preserve order.
- Numbers: only safe integers; monetary values must be strings.
- Omit keys whose value is `undefined`.
- Strings: UTF-8; hex strings should be lowercase unless specified otherwise.

