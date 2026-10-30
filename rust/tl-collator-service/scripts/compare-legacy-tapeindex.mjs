// Prints what the pinned legacy src/tapeIndex.ts (blob d12b1c53) produces for fixed inputs.
// Needs a Node with type stripping (Node >= 22.6 with --experimental-strip-types, or Node 24):
//   node scripts/compare-legacy-tapeindex.mjs > tests/fixtures/tapeindex_legacy.json
// The legacy file is imported unchanged; it only reads the temp tape written here.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const legacy = await import(pathToFileURL(path.resolve(here, '../../../src/tapeIndex.ts')).href);

const LINES = 53;
const line = (seq) => `{"v":1,"seq":${seq},"pad":"${'x'.repeat(seq % 7)}"}\n`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-idx-'));
const tape = path.join(dir, 'tape.log');
fs.writeFileSync(tape, Array.from({ length: LINES }, (_, i) => line(i + 1)).join(''));

const cases = [];
for (const stride of [1, 2, 3, 7, 10, 1000]) {
  const idx = legacy.buildIndex(tape, stride);
  const finds = [];
  for (let from = 0; from <= 60; from++) finds.push([from, legacy.findStartOffset(idx, from)]);
  cases.push({ stride, tapeSize: idx.tapeSize, offsets: idx.offsets, fresh: legacy.isIndexFresh(idx, tape), finds });
}
fs.rmSync(dir, { recursive: true, force: true });
process.stdout.write(JSON.stringify({ blob: 'd12b1c53', lines: LINES, cases }, null, 1) + '\n');
