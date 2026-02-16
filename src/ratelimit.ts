export class TokenBucket {
  private capacity: number;
  private refillPerSec: number;
  private tokens: number;
  private lastRefillMs: number;

  constructor(opts: { capacity: number; refillPerSec: number }) {
    this.capacity = Math.max(1, opts.capacity);
    this.refillPerSec = Math.max(0, opts.refillPerSec);
    this.tokens = this.capacity;
    this.lastRefillMs = Date.now();
  }

  allow(cost: number = 1): boolean {
    const now = Date.now();
    const dt = Math.max(0, now - this.lastRefillMs);
    const add = (dt / 1000) * this.refillPerSec;
    if (add > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + add);
      this.lastRefillMs = now;
    }
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }
}

