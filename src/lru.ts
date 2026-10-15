export class LruMap<V> {
  private max: number;
  private m = new Map<string, V>();

  constructor(max: number) {
    this.max = Math.max(1, max);
  }

  get(k: string): V | undefined {
    const v = this.m.get(k);
    if (v === undefined) return undefined;
    // refresh recency
    this.m.delete(k);
    this.m.set(k, v);
    return v;
  }

  set(k: string, v: V) {
    if (this.m.has(k)) this.m.delete(k);
    this.m.set(k, v);
    if (this.m.size > this.max) {
      const oldest = this.m.keys().next().value;
      if (oldest) this.m.delete(oldest);
    }
  }
}
