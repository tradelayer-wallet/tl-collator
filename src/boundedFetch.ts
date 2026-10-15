/**
 * Outbound JSON calls with a deadline and a body cap (round 8).
 *
 * Plain `fetch` has neither. A stalled upstream (IP intel, clearlist, the legacy relayer)
 * held a SUBMIT or an HTTP request open forever, and a large or endless body was buffered
 * whole. Here one AbortController covers the headers and the body, the body is read with a
 * byte limit, and redirects are refused so a configured host can not send the caller to
 * another one.
 */

export class BoundedFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BoundedFetchError';
  }
}

export interface BoundedFetchOptions {
  timeoutMs: number;
  maxBytes: number;
}

export interface BoundedFetchResult {
  status: number;
  ok: boolean;
  /** Parsed JSON when the body is JSON, otherwise the body text (empty body gives null). */
  body: any;
}

export async function fetchBoundedJson(
  url: string | URL,
  init: { method?: string; headers?: Record<string, string>; body?: string },
  opts: BoundedFetchOptions,
): Promise<BoundedFetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new BoundedFetchError('upstream deadline exceeded')), opts.timeoutMs);
  try {
    const res = await fetch(url, { ...init, redirect: 'error', signal: controller.signal });
    const text = await readCapped(res, opts.maxBytes, controller);
    return { status: res.status, ok: res.ok, body: parseBody(text) };
  } finally {
    clearTimeout(timer);
  }
}

async function readCapped(res: Response, maxBytes: number, controller: AbortController): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      controller.abort(new BoundedFetchError('upstream body too large'));
      await reader.cancel().catch(() => {});
      throw new BoundedFetchError('upstream body too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString('utf8');
}

function parseBody(text: string): any {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
