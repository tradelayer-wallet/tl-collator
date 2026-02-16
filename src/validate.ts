import type { OrderEnvelopeV1, WireMsg } from './types.js';

export function isWireMsg(x: any): x is WireMsg {
  return !!x && typeof x === 'object' && typeof x.t === 'string' && typeof x.v === 'number';
}

export function validateOrderEnvelope(o: any): o is OrderEnvelopeV1 {
  if (!o || typeof o !== 'object') return false;
  if (o.v !== 1) return false;
  if (!['NEW', 'CANCEL', 'REPLACE'].includes(o.kind)) return false;
  if (!o.body || typeof o.body !== 'object' || o.body.v !== 1) return false;
  if (typeof o.body.market !== 'string' || !o.body.market) return false;
  if (o.body.side !== 'BUY' && o.body.side !== 'SELL') return false;
  if (typeof o.body.px !== 'string' || typeof o.body.qty !== 'string') return false;
  if (!o.body.visibility || typeof o.body.visibility.kind !== 'string') return false;
  if (typeof o.body.clientTs !== 'number') return false;
  if (typeof o.traderPubKey !== 'string' || typeof o.clientNonce !== 'string') return false;
  if (typeof o.orderId !== 'string' || typeof o.sigTrader !== 'string') return false;
  // Basic hex sanity.
  if (!/^[0-9a-fA-F]+$/.test(o.orderId) || o.orderId.length !== 64) return false;
  if (!/^[0-9a-fA-F]+$/.test(o.sigTrader) || o.sigTrader.length !== 128) return false;
  if (!/^[0-9a-fA-F]+$/.test(o.traderPubKey)) return false;
  return true;
}

