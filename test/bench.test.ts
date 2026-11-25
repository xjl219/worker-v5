import { describe, expect, it } from "vitest";
import { buildV1Request, encodeWsClientFrame, parseWsServerFrames } from "../scripts/bench.mjs";
import { decodeEarlyDataHeader, parseV1Request } from "../src/index";

const UUID = "00000000-0000-4000-8000-000000000001";

describe("benchmark protocol helpers", () => {
  it("builds a VLESS request accepted by parseV1Request and 0-RTT early data decoder", () => {
    const payload = Buffer.from("GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\n\r\n", "utf8");
    const frame = buildV1Request(UUID, "cp.cloudflare.com", 80, payload);

    const parsed = parseV1Request(new Uint8Array(frame), UUID);
    expect(parsed.hostname).toBe("cp.cloudflare.com");
    expect(parsed.port).toBe(80);
    expect(Buffer.from(parsed.payload).toString("utf8")).toBe(payload.toString("utf8"));

    const b64url = frame.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const decoded = decodeEarlyDataHeader(b64url);
    expect(decoded).not.toBeNull();
    expect(parseV1Request(decoded!, UUID).hostname).toBe("cp.cloudflare.com");
  });

  it("round-trips RFC 6455 frames including 16-bit extended payload lengths and split buffers", () => {
    const small = Buffer.from([0x00, 0x00, 0x48, 0x54, 0x54, 0x50]);
    const medium = Buffer.alloc(300, 0xab);
    const wire = Buffer.concat([encodeWsClientFrame(small), encodeWsClientFrame(medium)]);

    const partial = parseWsServerFrames(wire.subarray(0, wire.length - 10));
    expect(partial.frames).toHaveLength(1);
    expect(partial.frames[0].payload.equals(small)).toBe(true);

    const rest = parseWsServerFrames(Buffer.concat([partial.remaining, wire.subarray(wire.length - 10)]));
    expect(rest.frames).toHaveLength(1);
    expect(rest.frames[0].payload.equals(medium)).toBe(true);
    expect(rest.remaining.length).toBe(0);
  });
});
