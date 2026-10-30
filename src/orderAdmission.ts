import { computeEnvelopeHash } from './canonical.js';
import { verifyTraderSig } from './crypto.js';
import type { ClearlistResult } from './clearlist.js';
import { intelAdmits, type IpIntel } from './ipIntel.js';
import { logInternalError } from './log.js';
import type { SessionMetaV1 } from './peerSession.js';
import type { OrderEnvelopeV1 } from './types.js';

export interface AdmissionPolicy {
  vpnFilterMode: 'off' | 'log' | 'reject';
  asnBlockMode: 'off' | 'log' | 'reject';
  asnBlocklist: number[];
  clearlistEnforce: boolean;
  clearlistFailMode: 'open' | 'closed';
}

// What admission reads from the collator's state. TapeStore, IpIntelClient and ClearlistClient satisfy these.
export interface AdmissionSources {
  tape: {
    hasOrder(orderId: string): boolean;
    getTraderForOrderId(orderId: string): string | null;
  };
  intel: { lookup(ip: string): Promise<IpIntel> } | null;
  clearlist: { check(groupId: string, pubkeyHex: string): Promise<ClearlistResult> } | null;
}

export interface AdmissionRefusal {
  code: string;
  msg: string;
}

const refuse = (code: string, msg: string): AdmissionRefusal => ({ code, msg });

/**
 * Every check a SUBMIT must pass before it is appended, in the order a refusal is reported. Returns
 * the first refusal, or null when the order may be appended. The atomic duplicate check stays with
 * TapeStore.append, because the awaits here let an identical SUBMIT land first.
 *
 * `meta` receives the intel verdict (asn, vpn) for this session as a side effect.
 */
export async function admitOrder(
  policy: AdmissionPolicy,
  src: AdmissionSources,
  meta: SessionMetaV1,
  order: OrderEnvelopeV1,
): Promise<AdmissionRefusal | null> {
  // Fast path only; the authoritative check is the atomic one in tape.append.
  if (src.tape.hasOrder(order.orderId)) return refuse('DUPLICATE', 'orderId already seen');
  if (!verifyTraderSig(order.orderId, order.sigTrader, order.traderPubKey)) {
    return refuse('bad_sig', 'sigTrader verify failed');
  }
  // C1: bind sigTrader to the whole envelope. orderId must be the canonical derivation over every
  // envelope field except orderId/sigTrader (TL-Canon v1), including kind, cancelsOrderId and
  // replacesOrderId, otherwise a harvested (orderId, sigTrader, traderPubKey, body) could be replayed
  // with a forged CANCEL/REPLACE after a collator restart.
  if (order.orderId !== computeEnvelopeHash(order)) {
    return refuse(
      'bad_order_id',
      'orderId must equal sha256(stableStringify(envelope minus orderId/sigTrader)), lowercase hex',
    );
  }

  // Basic referential integrity: prevent third-party cancels/replaces.
  if (order.kind === 'CANCEL') {
    const target = String(order.cancelsOrderId || '').trim();
    if (!target) return refuse('SCHEMA_INVALID', 'missing cancelsOrderId');
    const owner = src.tape.getTraderForOrderId(target);
    if (!owner) return refuse('UNKNOWN_ORDER', 'cancelsOrderId not found');
    if (owner !== order.traderPubKey.toLowerCase()) return refuse('NOT_OWNER', 'cannot cancel other trader order');
  } else if (order.kind === 'REPLACE') {
    const target = String(order.replacesOrderId || '').trim();
    if (!target) return refuse('SCHEMA_INVALID', 'missing replacesOrderId');
    const owner = src.tape.getTraderForOrderId(target);
    if (!owner) return refuse('UNKNOWN_ORDER', 'replacesOrderId not found');
    if (owner !== order.traderPubKey.toLowerCase()) return refuse('NOT_OWNER', 'cannot replace other trader order');
  }

  // IP intel policy. A reject mode admits only on a usable answer (intelAdmits): a failed lookup, no
  // client IP, or no intel source refuses the order. Log modes never refuse on intel.
  if (policy.vpnFilterMode !== 'off' || policy.asnBlockMode !== 'off') {
    let intel: IpIntel | null = null;
    if (src.intel && meta.remoteIp) {
      try {
        intel = await src.intel.lookup(meta.remoteIp);
        if (typeof intel.asn === 'number') meta.asn = intel.asn;
        if (typeof intel.vpn === 'boolean') meta.vpn = intel.vpn;
      } catch (e: any) {
        logInternalError('ip-intel-lookup', e);
      }
    }
    if (!intelAdmits(policy, intel)) return refuse('INTEL_UNAVAILABLE', 'ip intel unavailable');
  }
  if (policy.vpnFilterMode !== 'off' && meta.vpn === true && policy.vpnFilterMode === 'reject') {
    return refuse('VPN_BLOCKED', 'vpn traffic rejected');
  }
  if (
    policy.asnBlockMode !== 'off'
    && typeof meta.asn === 'number'
    && policy.asnBlocklist.includes(meta.asn)
    && policy.asnBlockMode === 'reject'
  ) {
    return refuse('ASN_BLOCKED', 'asn blocked');
  }

  if (policy.clearlistEnforce) {
    const vis: any = order?.body?.visibility;
    const kind = vis?.kind;
    const groupId = vis?.groupId;
    if ((kind === 'CLEARLIST' || kind === 'DARK') && typeof groupId === 'string' && groupId) {
      if (!src.clearlist) return refuse('CLEARLIST_DOWN', 'clearlist unavailable');
      try {
        const res = await src.clearlist.check(groupId, order.traderPubKey.toLowerCase());
        if (!res.allowed) return refuse('NOT_CLEARLISTED', 'not clearlisted');
      } catch (e: any) {
        if (policy.clearlistFailMode === 'closed') {
          logInternalError('clearlist-down', e);
          return refuse('CLEARLIST_DOWN', 'clearlist unavailable');
        }
      }
    }
  }
  return null;
}
