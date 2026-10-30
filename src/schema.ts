import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import type { SignalMsg } from './types.js';
import type { OrderEnvelopeV1 } from './types.js';
import { findCanonicalViolation } from './canonical.js';

export interface WireRefusal {
  code: string;
  msg: string;
}

export interface SchemaValidators {
  validateSignalMsg: (x: any) => x is SignalMsg;
  /** The ERR a DataChannel message earns, or null when it is a valid WireMsg. */
  wireRefusal: (x: any) => WireRefusal | null;
  validateOrderEnvelope: (x: any) => x is OrderEnvelopeV1;
  errorsText: () => string;
}

function loadJson(p: string): any {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

export function loadValidators(): SchemaValidators {
  const require = createRequire(import.meta.url);
  const Ajv2020 = require('ajv/dist/2020.js').default as any;
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(here, '..');
  const specDir = path.join(root, 'spec', 'schemas');

  const ajv = new Ajv2020({
    // Keep this permissive; these are interoperability schemas, not a closed-world API.
    // Some Ajv type definitions differ across builds, so keep options minimal.
    allErrors: false,
    allowUnionTypes: true,
  } as any);

  // Load and register schemas by $id.
  const manifest = loadJson(path.join(specDir, 'manifest.v1.schema.json'));
  const signalmsg = loadJson(path.join(specDir, 'signalmsg.v1.schema.json'));
  const wiremsg = loadJson(path.join(specDir, 'wiremsg.v1.schema.json'));
  const orderEnv = loadJson(path.join(specDir, 'order-envelope.v1.schema.json'));
  const tapeEntry = loadJson(path.join(specDir, 'tape-entry.v1.schema.json'));

  // Ajv resolves refs by $id; add all first.
  ajv.addSchema(manifest);
  ajv.addSchema(signalmsg);
  ajv.addSchema(wiremsg);
  ajv.addSchema(orderEnv);
  ajv.addSchema(tapeEntry);

  const vSignal = ajv.getSchema(signalmsg.$id) || ajv.compile(signalmsg);
  const vWire = ajv.getSchema(wiremsg.$id) || ajv.compile(wiremsg);
  const vOrder = ajv.getSchema(orderEnv.$id) || ajv.compile(orderEnv);

  let lastErrors: any[] | null = null;

  return {
    validateSignalMsg: (x: any): x is SignalMsg => {
      const ok = !!vSignal(x);
      lastErrors = ok ? null : (vSignal.errors || null);
      return ok;
    },
    wireRefusal: (x: any): WireRefusal | null => {
      if (vWire(x)) return null;
      lastErrors = vWire.errors || null;
      // A TAPE_SUB names the replay's start, so a bad fromSeq is refused as such and never coerced.
      if (x?.t === 'TAPE_SUB') return { code: 'bad_request', msg: 'invalid TAPE_SUB: fromSeq must be a non-negative safe integer' };
      return { code: 'SCHEMA_INVALID', msg: 'invalid WireMsg schema' };
    },
    validateOrderEnvelope: (x: any): x is OrderEnvelopeV1 => {
      // Reject values TL-Canon cannot represent anywhere in the envelope
      // (incl. the open-ended body): prototype-pollution keys, non-safe-integer
      // numbers and lone surrogates. Runs before schema validation so nothing
      // unhashable or unsafe reaches hashing or downstream object handling.
      const violation = findCanonicalViolation(x);
      if (violation !== null) {
        lastErrors = [{ instancePath: '', message: violation, params: {} }];
        return false;
      }
      const ok = !!vOrder(x);
      lastErrors = ok ? null : (vOrder.errors || null);
      return ok;
    },
    errorsText: () => ajv.errorsText(lastErrors || undefined, { separator: '; ' }),
  };
}
