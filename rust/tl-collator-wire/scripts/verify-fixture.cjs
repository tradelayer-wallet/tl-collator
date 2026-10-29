'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const dir=path.resolve(__dirname,'../fixtures');
const upstream=JSON.parse(fs.readFileSync(path.join(dir,'upstream-pr2-vectors.json'),'utf8'));
const curated=JSON.parse(fs.readFileSync(path.join(dir,'curated-vectors.json'),'utf8'));
const fields=['orderTest','orderCancelTest','integerKeyTest','orderIntegerKeyTest','unicodeKeyOrderTest',
  'integralNumberTest','tapeTest','rejectTests','textRejectTests','textAcceptTests'];
const want={};
for(const f of fields) want[f]= f==='rejectTests'?upstream[f].slice(0,3):upstream[f];
assert.deepEqual(curated,want,'Curated fixtures drifted from pinned PR #2 reference');
assert.equal(upstream.orderTest.expectedOrderId,'64496beee789330938912bb4fbef934e4dcb6bd3eabfe50d6a2786cd4fde71b4');
console.log('Pinned upstream TL-Canon v1 reference fixture integrity: OK');
