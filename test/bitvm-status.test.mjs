import assert from 'assert';

import { buildBitvmStatusFromArtifacts } from '../dist/bitvmStatus.js';

function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    console.error(`not ok - ${name}`);
    throw err;
  }
}

test('builds desktop-wallet compatible BitVM procedural status from referee artifacts', () => {
  const status = buildBitvmStatusFromArtifacts({ propertyId: 380 });

  assert.strictEqual(status.source, 'bitvmArtifacts');
  assert.strictEqual(status.commitScheme, 'bitvm-dlc-procedural-receipt');
  assert.strictEqual(status.procedural.ready, true, status.procedural.contextErrors?.join('\n'));
  assert.strictEqual(status.procedural.executionContextReady, true);
  assert.strictEqual(status.procedural.chainId, 'litecoin-testnet');
  assert.strictEqual(status.procedural.receiptPropertyId, 380);
  assert.strictEqual(status.procedural.receiptTicker, 'rLTC-SAT');
  assert.strictEqual(status.procedural.templateId, 'dlc-receipt-ltc-testnet-v1');
  assert.strictEqual(status.procedural.templateHash, '60e19d0c4f34a09a690e679230bf41a63252306e0e06a09e1b090efbcbb7b499');
  assert.strictEqual(status.procedural.contractId, 'ltc-testnet-epoch-1-1777140673550');
  assert.strictEqual(status.procedural.fundingTxid, '2edb992eade4f6fa7c3f9849a7f4390e839522f9b07d7b4e08ee33550a4eb2fe');
  assert.strictEqual(status.procedural.fundingVout, 0);
  assert.strictEqual(status.procedural.selectedPathId, 'roll');
  assert.strictEqual(status.procedural.selectedPathTxid, '5ca3395ceb0e80fa0b612fd7716ebbcd9027c428fd8c357f374fffc568fe61f2');
  assert.match(status.procedural.executionContextId, /^litecoin-testnet:[0-9a-f]{64}:roll$/);
  assert.match(status.procedural.executionContextHash, /^[0-9a-f]{64}$/);
  assert.deepStrictEqual(status.procedural.contextErrors, []);
});

test('unknown procedural property returns non-ready status instead of throwing', () => {
  const status = buildBitvmStatusFromArtifacts({ propertyId: 999999 });

  assert.strictEqual(status.source, 'bitvmArtifacts');
  assert.strictEqual(status.featureEnabled, false);
  assert.strictEqual(status.procedural.ready, false);
  assert.strictEqual(status.procedural.executionContextReady, false);
  assert.match(status.procedural.contextErrors[0], /propertyId 999999/);
});
