import { describe, expect, it } from "vitest";
import { toBytes } from "../src/index";

describe("WebSocket binary frame decoding", () => {
  it("decodes ArrayBuffer frames", async () => {
    const source = new Uint8Array([0, 1, 2, 255]);
    expect(Array.from(await toBytes(source.buffer))).toEqual([0, 1, 2, 255]);
  });

  it("preserves the byte offset and length of typed-array views", async () => {
    const source = new Uint8Array([9, 8, 7, 6]);
    expect(Array.from(await toBytes(source.subarray(1, 3)))).toEqual([8, 7]);
  });

  it("decodes Blob frames delivered by the Workers standard binary type", async () => {
    const source = new Blob([new Uint8Array([0, 0, 1, 2, 255])]);
    expect(Array.from(await toBytes(source))).toEqual([0, 0, 1, 2, 255]);
  });

  it("rejects text frames instead of coercing them into binary", async () => {
    await expect(toBytes("not a binary frame")).rejects.toThrow(
      "Only binary WebSocket messages are supported",
    );
  });
});
