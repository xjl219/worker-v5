import { describe, expect, it } from "vitest";
import { CircuitBreakerRegistry } from "../src/index";

describe("CircuitBreakerRegistry", () => {
  it("opens after the configured consecutive failure threshold", () => {
    const breaker = new CircuitBreakerRegistry({ failureThreshold: 2, resetTimeoutMs: 100 });
    expect(breaker.tryAcquire("relay-a", 0)).toBe(true);
    breaker.recordFailure("relay-a", 1);
    expect(breaker.state("relay-a", 1)).toBe("closed");
    breaker.recordFailure("relay-a", 2);
    expect(breaker.state("relay-a", 2)).toBe("open");
    expect(breaker.tryAcquire("relay-a", 50)).toBe(false);
  });

  it("allows only one half-open probe after the reset timeout", () => {
    const breaker = new CircuitBreakerRegistry({ failureThreshold: 1, resetTimeoutMs: 100 });
    breaker.recordFailure("relay-a", 0);
    expect(breaker.state("relay-a", 99)).toBe("open");
    expect(breaker.state("relay-a", 100)).toBe("half-open");
    expect(breaker.tryAcquire("relay-a", 100)).toBe(true);
    expect(breaker.tryAcquire("relay-a", 101)).toBe(false);
  });

  it("closes after a successful half-open probe", () => {
    const breaker = new CircuitBreakerRegistry({ failureThreshold: 1, resetTimeoutMs: 10 });
    breaker.recordFailure("relay-a", 0);
    expect(breaker.tryAcquire("relay-a", 10)).toBe(true);
    breaker.recordSuccess("relay-a");
    expect(breaker.state("relay-a", 11)).toBe("closed");
    expect(breaker.tryAcquire("relay-a", 11)).toBe(true);
  });

  it("reopens when a half-open probe fails", () => {
    const breaker = new CircuitBreakerRegistry({ failureThreshold: 1, resetTimeoutMs: 10 });
    breaker.recordFailure("relay-a", 0);
    expect(breaker.tryAcquire("relay-a", 10)).toBe(true);
    breaker.recordFailure("relay-a", 10);
    expect(breaker.state("relay-a", 19)).toBe("open");
    expect(breaker.tryAcquire("relay-a", 19)).toBe(false);
  });

  it("tracks endpoints independently", () => {
    const breaker = new CircuitBreakerRegistry({ failureThreshold: 1, resetTimeoutMs: 100 });
    breaker.recordFailure("relay-a", 0);
    expect(breaker.tryAcquire("relay-a", 1)).toBe(false);
    expect(breaker.tryAcquire("relay-b", 1)).toBe(true);
  });
});
