import type { WireMsg } from './types.js';

export function isWireMsg(x: any): x is WireMsg {
  return !!x && typeof x === 'object' && typeof x.t === 'string' && typeof x.v === 'number';
}
