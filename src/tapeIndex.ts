import fs from 'node:fs';

export interface TapeIndex {
  stride: number;
  tapeSize: number;
  // offsets[i] is byte offset of the line whose seq == (i*stride + 1)
  offsets: number[];
}

export function loadIndex(idxPath: string): TapeIndex | null {
  try {
    if (!fs.existsSync(idxPath)) return null;
    const raw = fs.readFileSync(idxPath, 'utf8');
    const j = JSON.parse(raw);
    if (!j || typeof j.stride !== 'number' || !Array.isArray(j.offsets) || typeof j.tapeSize !== 'number') return null;
    return { stride: j.stride, tapeSize: j.tapeSize, offsets: j.offsets.map((n: any) => Number(n) || 0) };
  } catch {
    return null;
  }
}

export function saveIndex(idxPath: string, idx: TapeIndex) {
  fs.writeFileSync(idxPath, JSON.stringify(idx), 'utf8');
}

export function isIndexFresh(idx: TapeIndex, tapePath: string): boolean {
  try {
    const st = fs.statSync(tapePath);
    return st.size === idx.tapeSize;
  } catch {
    return false;
  }
}

// Build index by scanning tape once.
export function buildIndex(tapePath: string, stride: number): TapeIndex {
  const s = fs.existsSync(tapePath) ? fs.readFileSync(tapePath) : Buffer.alloc(0);
  const offsets: number[] = [];
  let lineStart = 0;
  let seq = 0;

  for (let i = 0; i < s.length; i++) {
    if (s[i] !== 0x0a) continue; // '\n'
    const line = s.slice(lineStart, i).toString('utf8').trim();
    lineStart = i + 1;
    if (!line) continue;
    try {
      const obj = JSON.parse(line);
      if (typeof obj.seq === 'number') seq = obj.seq;
      // Index every stride entries (seq 1, 1001, 2001...)
      if (seq === 1 || (seq - 1) % stride === 0) offsets.push(i - Buffer.byteLength(line) /* approx */);
    } catch {
      // ignore
    }
  }

  // The "approx" above is not reliable; do a correct pass computing offsets precisely.
  // Recompute offsets accurately by walking lines and tracking byte positions.
  const accurate: number[] = [];
  let pos = 0;
  seq = 0;
  const buf = s;
  while (pos < buf.length) {
    const nl = buf.indexOf(0x0a, pos);
    const end = nl === -1 ? buf.length : nl;
    const raw = buf.slice(pos, end).toString('utf8').trim();
    const thisOffset = pos;
    pos = nl === -1 ? buf.length : nl + 1;
    if (!raw) continue;
    try {
      const obj = JSON.parse(raw);
      if (typeof obj.seq === 'number') seq = obj.seq;
      if (seq === 1 || (seq - 1) % stride === 0) accurate.push(thisOffset);
    } catch {}
  }

  return { stride, tapeSize: buf.length, offsets: accurate };
}

export function findStartOffset(idx: TapeIndex, fromSeq: number): number {
  if (fromSeq <= 1) return 0;
  const block = Math.floor((fromSeq - 1) / idx.stride);
  const off = idx.offsets[block];
  return typeof off === 'number' ? off : 0;
}

