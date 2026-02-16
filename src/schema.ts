import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import type { SignalMsg, WireMsg } from './types.js';
import type { OrderEnvelopeV1 } from './types.js';

export interface SchemaValidators {
  validateSignalMsg: (x: any) => x is SignalMsg;
  validateWireMsg: (x: any) => x is WireMsg;
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
    validateWireMsg: (x: any): x is WireMsg => {
      const ok = !!vWire(x);
      lastErrors = ok ? null : (vWire.errors || null);
      return ok;
    },
    validateOrderEnvelope: (x: any): x is OrderEnvelopeV1 => {
      const ok = !!vOrder(x);
      lastErrors = ok ? null : (vOrder.errors || null);
      return ok;
    },
    errorsText: () => ajv.errorsText(lastErrors || undefined, { separator: '; ' }),
  };
}
