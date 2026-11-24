export type CircuitState = "closed" | "open" | "half-open";

type Entry = {
  failures: number;
  openedAt: number | null;
  probeInFlight: boolean;
};

export type CircuitBreakerOptions = {
  failureThreshold?: number;
  resetTimeoutMs?: number;
};

const DEFAULT_FAILURE_THRESHOLD = 3;
const DEFAULT_RESET_TIMEOUT_MS = 30_000;

/**
 * Isolate-local circuit breaker. It deliberately does not claim global
 * coordination across Cloudflare Worker isolates.
 */
export class CircuitBreakerRegistry {
  private readonly entries = new Map<string, Entry>();
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;

  constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD;
    this.resetTimeoutMs = options.resetTimeoutMs ?? DEFAULT_RESET_TIMEOUT_MS;
    if (!Number.isInteger(this.failureThreshold) || this.failureThreshold < 1) {
      throw new Error("failureThreshold must be a positive integer");
    }
    if (!Number.isFinite(this.resetTimeoutMs) || this.resetTimeoutMs < 1) {
      throw new Error("resetTimeoutMs must be positive");
    }
  }

  state(key: string, now = Date.now()): CircuitState {
    const entry = this.entries.get(key);
    if (!entry) return "closed";
    if (entry.openedAt === null) return "closed";
    if (now - entry.openedAt >= this.resetTimeoutMs) return "half-open";
    return "open";
  }

  tryAcquire(key: string, now = Date.now()): boolean {
    const entry = this.entries.get(key);
    if (!entry) {
      this.entries.set(key, { failures: 0, openedAt: null, probeInFlight: false });
      return true;
    }
    if (entry.openedAt === null) return true;
    if (now - entry.openedAt < this.resetTimeoutMs || entry.probeInFlight) return false;
    entry.probeInFlight = true;
    return true;
  }

  recordSuccess(key: string): void {
    this.entries.set(key, { failures: 0, openedAt: null, probeInFlight: false });
  }

  recordFailure(key: string, now = Date.now()): void {
    const entry = this.entries.get(key) ?? { failures: 0, openedAt: null, probeInFlight: false };
    entry.failures += 1;
    if (entry.openedAt !== null || entry.failures >= this.failureThreshold) {
      entry.openedAt = now;
      entry.probeInFlight = false;
    }
    this.entries.set(key, entry);
  }
}
