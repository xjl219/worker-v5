import { describe, expect, it } from "vitest";
import { parseV1Request, encodeS5Address } from "../src/v1-s5";
import { isAllowedDestinationHost, normalizeDestinationHostname, parseAllowedHosts } from "../src/security";

const UUID = "00000000-0000-4000-8000-000000000001";

function makeRequest(host: string, port = 443, addressType = 2): Uint8Array {
  const uuid = UUID.replaceAll("-", "").match(/.{2}/g)!.map((x) => Number.parseInt(x, 16));
  if (addressType === 1) {
    const octets = host.split(".").map(Number);
    return new Uint8Array([0, ...uuid, 0, 1, (port >> 8) & 0xff, port & 0xff, 1, ...octets]);
  }
  const domain = new TextEncoder().encode(host);
  return new Uint8Array([0, ...uuid, 0, 1, (port >> 8) & 0xff, port & 0xff, 2, domain.length, ...domain]);
}

describe("V1 request parser", () => {
  it("parses a domain TCP request", () => {
    const result = parseV1Request(makeRequest("example.com"), UUID);
    expect(result.hostname).toBe("example.com");
    expect(result.port).toBe(443);
  });

  it("rejects an incorrect UUID", () => {
    expect(() => parseV1Request(makeRequest("example.com"), "10000000-0000-4000-8000-000000000001"))
      .toThrow("Invalid V1 UUID");
  });

  it.each(["", "not-a-uuid", "00000000-0000-4000-8000-00000000000z"])(
    "rejects an absent or malformed configured UUID (%s)",
    (configuredUuid) => {
      expect(() => parseV1Request(makeRequest("example.com"), configuredUuid))
        .toThrow("UUID must be a valid");
    },
  );

  it.each(["10.0.0.1", "127.0.0.1", "169.254.1.1", "192.168.1.1", "100.64.0.1", "198.18.0.1", "203.0.113.1"])(
    "rejects non-public IPv4 destination %s", (host) => {
      expect(() => parseV1Request(makeRequest(host, 443, 1), UUID)).toThrow("Private or local");
    },
  );

  it.each(["2130706433", "127.1", "0177.0.0.1", "999.999.999.999", "localhost", "host..example.com"])(
    "rejects non-canonical or non-public numeric/domain destination %s", (host) => {
      expect(() => parseV1Request(makeRequest(host), UUID)).toThrow();
    },
  );

  it("rejects malformed UTF-8 in a domain destination", () => {
    const data = makeRequest("example.com");
    data[23] = 0xff;
    expect(() => parseV1Request(data, UUID)).toThrow();
  });

  it("rejects UDP command", () => {
    const data = makeRequest("example.com");
    data[18] = 2;
    expect(() => parseV1Request(data, UUID)).toThrow("Only V1 TCP");
  });
});


describe("S5 destination address encoding", () => {
  it("encodes IPv4 as ATYP 1 with four address octets", () => {
    expect(Array.from(encodeS5Address("8.8.4.4"))).toEqual([1, 8, 8, 4, 4]);
  });

  it("encodes domains as ATYP 3", () => {
    expect(Array.from(encodeS5Address("example.com"))).toEqual([
      3, 11, ...new TextEncoder().encode("example.com"),
    ]);
  });

  it("encodes compressed IPv6 as ATYP 4 with sixteen address bytes", () => {
    const encoded = encodeS5Address("2001:db8::1");
    expect(encoded[0]).toBe(4);
    expect(encoded).toHaveLength(17);
    expect(Array.from(encoded.slice(1))).toEqual([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
  });
});


describe("destination hostname allowlist", () => {
  it("normalizes case and a terminal DNS dot before exact matching", () => {
    const allowed = parseAllowedHosts("Gemini.Google.com");
    expect(isAllowedDestinationHost("gemini.google.com.", allowed)).toBe(true);
  });

  it("authorizes only the exact configured hostname", () => {
    const allowed = parseAllowedHosts("google.com");
    expect(isAllowedDestinationHost("google.com", allowed)).toBe(true);
    expect(isAllowedDestinationHost("google.com.", allowed)).toBe(true);
    expect(isAllowedDestinationHost("sub.google.com", allowed)).toBe(false);
    expect(isAllowedDestinationHost("evilgoogle.com", allowed)).toBe(false);
    expect(isAllowedDestinationHost("google.com.evil.net", allowed)).toBe(false);
  });

  it("returns an empty set for a missing allowlist so callers can fail closed", () => {
    expect(parseAllowedHosts(undefined).size).toBe(0);
    expect(parseAllowedHosts("").size).toBe(0);
  });

  it("rejects wildcard entries and URL-like allowlist values", () => {
    expect(() => parseAllowedHosts("*.google.com")).toThrow();
    expect(() => parseAllowedHosts("https://google.com")).toThrow();
  });

  it.each(["localhost", "127.0.0.1", "2130706433", "a..google.com", "-bad.google.com"])(
    "rejects invalid or non-DNS destination %s", (host) => {
      expect(() => normalizeDestinationHostname(host)).toThrow();
    },
  );

  it("rejects empty allowlist entries instead of silently ignoring them", () => {
    expect(() => parseAllowedHosts("gemini.google.com,,api.anthropic.com")).toThrow();
  });
});
