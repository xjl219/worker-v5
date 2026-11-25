import { describe, expect, it } from "vitest";
import { decodeEarlyDataHeader, parseV1Request, SocketReader, toBytesSync } from "../src/index";

const UUID = "00000000-0000-4000-8000-000000000001";

function toBase64Url(bytes: Uint8Array, withPadding = false): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
  return withPadding ? encoded : encoded.replace(/=+$/, "");
}

function makeV1Frame(host: string, payload: Uint8Array, port = 443): Uint8Array {
  const uuid = UUID.replaceAll("-", "").match(/.{2}/g)!.map((x) => Number.parseInt(x, 16));
  const domain = new TextEncoder().encode(host);
  return new Uint8Array([0, ...uuid, 0, 1, (port >> 8) & 0xff, port & 0xff, 2, domain.length, ...domain, ...payload]);
}

function streamFromChunks(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}

describe("0-RTT early data header decoding", () => {
  it("decodes an unpadded base64url VLESS frame from Sec-WebSocket-Protocol", () => {
    const payload = new Uint8Array([0x16, 0x03, 0x01, 0xfe, 0xff]);
    const frame = makeV1Frame("example.com", payload);
    const decoded = decodeEarlyDataHeader(toBase64Url(frame, false));
    expect(decoded).not.toBeNull();
    const parsed = parseV1Request(decoded!, UUID);
    expect(parsed.hostname).toBe("example.com");
    expect(parsed.port).toBe(443);
    expect(Array.from(parsed.payload)).toEqual(Array.from(payload));
  });

  it("ignores absent, non-base64url, or short subprotocol tokens", () => {
    expect(decodeEarlyDataHeader(null)).toBeNull();
    expect(decodeEarlyDataHeader("")).toBeNull();
    expect(decodeEarlyDataHeader("vless")).toBeNull();
    expect(decodeEarlyDataHeader("chat, superchat")).toBeNull();
    expect(decodeEarlyDataHeader("not*valid!base64")).toBeNull();
  });
});

describe("synchronous binary frame fast path", () => {
  it("returns Uint8Array synchronously for ArrayBuffer and views, null for Blob or text", () => {
    const source = new Uint8Array([10, 20, 30, 40]);
    expect(Array.from(toBytesSync(source.buffer)!)).toEqual([10, 20, 30, 40]);
    expect(Array.from(toBytesSync(source.subarray(1, 3))!)).toEqual([20, 30]);
    expect(toBytesSync(new Blob([source]))).toBeNull();
    expect(toBytesSync("text")).toBeNull();
  });
});

describe("SocketReader streaming and backpressure", () => {
  it("reads exact handshake byte counts across split and coalesced chunks", async () => {
    const reader = new SocketReader(streamFromChunks([
      new Uint8Array([5, 0, 5, 0]),
      new Uint8Array([0, 1]),
      new Uint8Array([127, 0, 0, 1, 0x01, 0xbb, 0xaa, 0xbb]),
    ]));
    expect(Array.from(await reader.readExactly(2))).toEqual([5, 0]);
    expect(Array.from(await reader.readExactly(4))).toEqual([5, 0, 0, 1]);
    expect(Array.from(await reader.readExactly(6))).toEqual([127, 0, 0, 1, 0x01, 0xbb]);

    const sent: Uint8Array[] = [];
    const fakeWs = {
      readyState: 1,
      bufferedAmount: 0,
      send: (data: string | ArrayBuffer | ArrayBufferView) => {
        if (ArrayBuffer.isView(data)) {
          sent.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        }
      },
      close: () => { fakeWs.readyState = 3; },
    };
    await reader.pumpTo(fakeWs, () => false, () => {}, new Uint8Array([0, 0]));
    expect(sent).toHaveLength(1);
    expect(Array.from(sent[0])).toEqual([0, 0, 0xaa, 0xbb]);
  });

  it("prepends the VLESS response header only to the first downstream chunk", async () => {
    const reader = new SocketReader(streamFromChunks([
      new Uint8Array([1, 2, 3]),
      new Uint8Array([4, 5]),
    ]));
    const sent: number[][] = [];
    let activities = 0;
    const fakeWs = {
      readyState: 1,
      bufferedAmount: 0,
      send: (data: string | ArrayBuffer | ArrayBufferView) => {
        if (ArrayBuffer.isView(data)) {
          sent.push(Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)));
        }
      },
      close: () => { fakeWs.readyState = 3; },
    };

    await reader.pumpTo(fakeWs, () => false, () => { activities += 1; }, new Uint8Array([0, 0]));
    expect(activities).toBe(2);
    expect(sent).toEqual([[0, 0, 1, 2, 3], [4, 5]]);
  });

  it("pauses under high backpressure and resumes once the WebSocket drains", async () => {
    const reader = new SocketReader(streamFromChunks([
      new Uint8Array([1, 2]),
      new Uint8Array([3, 4]),
    ]));
    const sent: number[][] = [];
    let closedCode: number | undefined;
    let sleepCalls = 0;
    const fakeWs = {
      readyState: 1,
      bufferedAmount: 2048,
      send: (data: string | ArrayBuffer | ArrayBufferView) => {
        if (ArrayBuffer.isView(data)) {
          sent.push(Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)));
        }
      },
      close: (code?: number) => {
        closedCode = code;
        fakeWs.readyState = 3;
      },
    };

    await reader.pumpTo(fakeWs, () => false, () => {}, undefined, {
      highWaterBytes: 1024,
      maxBufferedBytes: 4096,
      maxWaitMs: 200,
      sleep: async () => {
        sleepCalls += 1;
        if (sleepCalls >= 2) fakeWs.bufferedAmount = 0;
      },
    });

    expect(sleepCalls).toBe(2);
    expect(closedCode).toBeUndefined();
    expect(sent).toEqual([[1, 2], [3, 4]]);
  });

  it("closes with 1013 when bufferedAmount remains above maxBufferedBytes past maxWaitMs", async () => {
    const reader = new SocketReader(streamFromChunks([new Uint8Array([1, 2, 3])]));
    const sent: number[][] = [];
    let closedCode: number | undefined;
    const fakeWs = {
      readyState: 1,
      bufferedAmount: 8192,
      send: (data: string | ArrayBuffer | ArrayBufferView) => {
        if (ArrayBuffer.isView(data)) {
          sent.push(Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)));
        }
      },
      close: (code?: number) => {
        closedCode = code;
        fakeWs.readyState = 3;
      },
    };

    await reader.pumpTo(fakeWs, () => false, () => {}, undefined, {
      highWaterBytes: 1024,
      maxBufferedBytes: 4096,
      maxWaitMs: 30,
      sleep: async () => {},
    });

    expect(closedCode).toBe(1013);
    expect(sent).toEqual([]);
  });
});
