import { connect } from "cloudflare:sockets";

// Circuit breaker
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

// Destination security and hostname allowlist
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function normalizeDestinationHostname(input: string): string {
  const host = input.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("*") || host.includes("/") ||
      host.includes("@") || host.includes(":") || host.includes("%") ||
      host.includes("\\") || /\s/.test(host)) {
    throw new Error("Destination must be a DNS hostname");
  }
  if (/^\d+(?:\.\d+){0,3}$/.test(host)) {
    throw new Error("IP-literal destinations are not allowed");
  }
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => !DOMAIN_LABEL.test(label))) {
    throw new Error("Invalid destination hostname");
  }
  return host;
}

export function normalizeParsedDestination(input: string): string {
  const host = input.trim().toLowerCase();
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) return host;
    throw new Error("Invalid IPv4 destination");
  }
  if (host.includes(":")) {
    const groups = host.split(":");
    if (groups.length === 8 && groups.every((part) => /^[0-9a-f]{1,4}$/.test(part))) return host;
    throw new Error("Invalid IPv6 destination");
  }
  return normalizeDestinationHostname(host);
}

export function parseAllowedHosts(raw: string | undefined): Set<string> {
  if (!raw?.trim()) return new Set();
  const entries = raw.split(",");
  const hosts = new Set<string>();
  for (const entry of entries) {
    const value = entry.trim();
    if (!value) throw new Error("AH contains an empty entry");
    hosts.add(normalizeDestinationHostname(value));
  }
  return hosts;
}

/**
 * Only the exact normalized hostname is authorized. Parent domains never
 * implicitly authorize subdomains.
 */
export function isAllowedDestinationHost(hostname: string, allowed: Set<string>): boolean {
  try {
    return allowed.has(normalizeDestinationHostname(hostname));
  } catch {
    return false;
  }
}

// V1 and S5 protocol codecs
export type ParsedRequest = {
  version: number;
  hostname: string;
  port: number;
  payload: Uint8Array;
};

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UTF8_ENCODER = new TextEncoder();

let cachedUuidRaw: string | undefined;
let cachedUuidBytes: Uint8Array | undefined;

function uuidToBytes(uuid: string): Uint8Array {
  if (uuid === cachedUuidRaw && cachedUuidBytes) return cachedUuidBytes;
  const hex = uuid.replaceAll("-", "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("UUID must be a valid 32-character UUID");
  const bytes = Uint8Array.from(hex.match(/.{2}/g)!, (part) => Number.parseInt(part, 16));
  cachedUuidRaw = uuid;
  cachedUuidBytes = bytes;
  return bytes;
}

function bytesToIPv6(bytes: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  return groups.join(":");
}

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return false;
  const [a, b, c] = parts.map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113);
}

function isPrivateIPv6(host: string): boolean {
  const groups = host.toLowerCase().split(":").map((part) => Number.parseInt(part || "0", 16));
  if (groups.length !== 8 || groups.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) return true;
  if (groups.every((part) => part === 0) || groups.slice(0, 7).every((part) => part === 0) && groups[7] === 1) return true;
  if ((groups[0] & 0xfe00) === 0xfc00 || (groups[0] & 0xffc0) === 0xfe80 || (groups[0] & 0xff00) === 0xff00) return true;
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) return true;
  if (groups.slice(0, 5).every((part) => part === 0) && groups[5] === 0xffff) {
    const ipv4 = [
      groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff,
    ].join(".");
    return isPrivateIPv4(ipv4);
  }
  return false;
}

export function parseV1Request(data: Uint8Array, expectedUuid: string): ParsedRequest {
  if (data.length < 22) throw new Error("Incomplete V1 request header");
  const expected = uuidToBytes(expectedUuid);
  let mismatch = 0;
  for (let i = 0; i < 16; i++) mismatch |= data[1 + i] ^ expected[i];
  if (mismatch !== 0) throw new Error("Invalid V1 UUID");

  const version = data[0];
  if (version !== 0x00) throw new Error("Unsupported V1 version");
  const addonLength = data[17];
  const commandOffset = 18 + addonLength;
  if (data.length < commandOffset + 4) throw new Error("Incomplete V1 address header");
  if (data[commandOffset] !== 0x01) throw new Error("Only V1 TCP command is supported");

  const port = (data[commandOffset + 1] << 8) | data[commandOffset + 2];
  const addressType = data[commandOffset + 3];
  let hostname: string;
  let addressLength: number;
  let addressOffset = commandOffset + 4;
  let privateAddress = false;

  if (addressType === 0x01) {
    addressLength = 4;
    if (data.length < addressOffset + addressLength) throw new Error("Incomplete IPv4 address");
    hostname = Array.from(data.subarray(addressOffset, addressOffset + 4)).join(".");
    privateAddress = isPrivateIPv4(hostname);
  } else if (addressType === 0x02) {
    if (data.length < addressOffset + 1) throw new Error("Incomplete domain length");
    addressLength = data[addressOffset++];
    if (addressLength < 1 || data.length < addressOffset + addressLength) throw new Error("Invalid domain address");
    const decodedHostname = UTF8_DECODER.decode(data.subarray(addressOffset, addressOffset + addressLength));
    hostname = normalizeDestinationHostname(decodedHostname);
  } else if (addressType === 0x03) {
    addressLength = 16;
    if (data.length < addressOffset + addressLength) throw new Error("Incomplete IPv6 address");
    const addressBytes = data.subarray(addressOffset, addressOffset + addressLength);
    hostname = bytesToIPv6(addressBytes);
    privateAddress = isPrivateIPv6(hostname);
  } else {
    throw new Error("Unsupported V1 address type");
  }

  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid destination port");
  if (hostname.length > 253 || /[^a-zA-Z0-9.\-_:]/.test(hostname)) throw new Error("Invalid destination hostname");
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "localhost" || normalized.endsWith(".localhost") ||
      normalized.endsWith(".local") || normalized.endsWith(".internal") ||
      privateAddress || isPrivateIPv4(normalized)) {
    throw new Error("Private or local destinations are not allowed");
  }

  const payloadOffset = addressOffset + addressLength;
  return { version, hostname, port, payload: data.subarray(payloadOffset) };
}

export function encodeS5Address(hostname: string): Uint8Array {
  const host = hostname;
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.some((part) => part < 0 || part > 255)) {
      throw new Error("Invalid IPv4 destination");
    }
    return new Uint8Array([1, ...octets]);
  }
  if (host.includes(":")) {
    const halves = host.split("::");
    if (halves.length > 2) throw new Error("Invalid IPv6 destination");
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
      throw new Error("Invalid IPv6 destination");
    }
    const groups = [...left, ...Array(missing).fill("0"), ...right];
    if (groups.length !== 8 || groups.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) {
      throw new Error("Invalid IPv6 destination");
    }
    const bytes = groups.flatMap((part) => {
      const value = Number.parseInt(part, 16);
      return [value >> 8, value & 255];
    });
    return new Uint8Array([4, ...bytes]);
  }
  const domain = UTF8_ENCODER.encode(host);
  if (!domain.length || domain.length > 255) throw new Error("Invalid S5 destination hostname");
  return new Uint8Array([3, domain.length, ...domain]);
}

// Public HTTP surface
function notFound(): Response {
  return new Response("Not found", { status: 404, headers: SECURITY_HEADERS });
}

function isSensitivePath(pathname: string): boolean {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname).toLowerCase();
  } catch {
    return true;
  }
  const normalized = decoded.replace(/\\/g, "/");
  return normalized.split("/").some((part) =>
    part === ".env" || part === ".git" || part === ".vscode" ||
    part === ".svn" || part === ".hg" || part === "actuator" ||
    part === "wp-admin" || part === "phpmyadmin"
  );
}

/**
 * Returns a response for every non-proxy request. A null result means the
 * request is the one allowed WebSocket upgrade endpoint and may reach the proxy.
 */
export function getPublicSurfaceResponse(request: Request, healthEnabled?: string): Response | null {
  const url = new URL(request.url);
  if (isSensitivePath(url.pathname) || request.method !== "GET") return notFound();

  if (url.pathname === "/health") {
    if (healthEnabled !== "true") return notFound();
    return Response.json({ ok: true }, { headers: SECURITY_HEADERS });
  }

  if (url.pathname === "/ws" && request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
    return null;
  }

  return notFound();
}

// Worker entry point and outbound transport
interface Env {
  UUID: string;
  AP?: string;
  AH?: string;
  PE?: string;
  HE?: string;
  OM?: string;
  RE?: string;
  H?: string;
  P?: string;
  SU?: string;
  SP?: string;
}

const DEFAULT_AP = [80, 443, 8080, 8443, 2053, 2083, 2087, 2096];
const DEFAULT_AP_SET = new Set(DEFAULT_AP);
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
const WS_BACKPRESSURE_HIGH_WATER_BYTES = 1 * 1024 * 1024;
const MAX_WS_BUFFERED_BYTES = 4 * 1024 * 1024;
const WS_BACKPRESSURE_MAX_WAIT_MS = 10_000;
const MAX_UPSTREAM_QUEUED_BYTES = 8 * 1024 * 1024;
const MAX_CONNECTIONS_PER_ISOLATE = 50;
const MAX_CONNECTION_LIFETIME_MS = 10 * 60 * 1000;
const IDLE_CONNECTION_TIMEOUT_MS = 2 * 60 * 1000;
const MIN_V1_HEADER_BYTES = 22;
const WS_OPEN_READY_STATE = 1;
let activeConnections = 0;

// Diagnostics are disabled in production. Never log raw frame prefixes: the
// initial VLESS frame contains credential bytes.
const DEBUG_LOG = false;

function debugLog(stage: string, details: Record<string, unknown> = {}): void {
  if (!DEBUG_LOG) return;
  console.log("[worker-v5:DEBUG]", {
    timestamp: new Date().toISOString(),
    stage,
    ...details,
  });
}

function debugError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return { errorName: error.name, errorMessage: error.message, errorStack: error.stack };
  }
  return { errorName: "UnknownError", errorMessage: String(error) };
}
const SECURITY_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

function response(body: BodyInit | null, status: number, headers?: HeadersInit): Response {
  const merged = new Headers(SECURITY_HEADERS);
  if (headers) new Headers(headers).forEach((value, key) => merged.set(key, value));
  return new Response(body, { status, headers: merged });
}

export function toBytesSync(data: unknown): Uint8Array | null {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return null;
}

export async function toBytes(data: unknown): Promise<Uint8Array> {
  const sync = toBytesSync(data);
  if (sync) return sync;
  // Cloudflare Workers may deliver binary frames as Blob when
  // websocket_standard_binary_type is enabled by the compatibility date.
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new Error("Only binary WebSocket messages are supported");
}

/**
 * Decodes optional VLESS WebSocket 0-RTT early data carried in the
 * Sec-WebSocket-Protocol header (base64url). Returns null when absent,
 * non-base64url, or shorter than a minimal V1 header.
 */
export function decodeEarlyDataHeader(header: string | null): Uint8Array | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/=]+$/.test(normalized)) return null;
  const mod = normalized.length % 4;
  if (mod === 1) return null;
  const padded = mod === 0 ? normalized : normalized + "=".repeat(4 - mod);
  try {
    const binary = atob(padded);
    if (binary.length < MIN_V1_HEADER_BYTES) return null;
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

let cachedAllowedHostsRaw: string | undefined;
let cachedAllowedHostsSet: Set<string> | undefined;

/**
 * An unset or empty AH disables only hostname allowlist matching.
 * A configured but malformed AH rejects the destination.
 */
export function isDestinationHostAllowed(hostname: string, rawAllowedHosts: string | undefined): boolean {
  if (!rawAllowedHosts?.trim()) return true;
  try {
    let allowed: Set<string>;
    if (rawAllowedHosts === cachedAllowedHostsRaw && cachedAllowedHostsSet) {
      allowed = cachedAllowedHostsSet;
    } else {
      allowed = parseAllowedHosts(rawAllowedHosts);
      cachedAllowedHostsRaw = rawAllowedHosts;
      cachedAllowedHostsSet = allowed;
    }
    return isAllowedDestinationHost(hostname, allowed);
  } catch {
    return false;
  }
}

let cachedAllowedPortsRaw: string | undefined;
let cachedAllowedPortsSet: Set<number> | undefined;

function allowedPorts(env: Env): Set<number> {
  const raw = env.AP?.trim();
  if (!raw) return DEFAULT_AP_SET;
  if (raw === cachedAllowedPortsRaw && cachedAllowedPortsSet) return cachedAllowedPortsSet;
  const ports = raw.split(",").map((value) => Number(value.trim()));
  if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error("AP contains an invalid port");
  }
  const set = new Set(ports);
  cachedAllowedPortsRaw = raw;
  cachedAllowedPortsSet = set;
  return set;
}

export type PumpBackpressureOptions = {
  highWaterBytes?: number;
  maxBufferedBytes?: number;
  maxWaitMs?: number;
  sleep?: (ms: number) => Promise<void>;
};

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export class SocketReader {
  private buffer: Uint8Array = new Uint8Array(0);
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;

  constructor(readable: ReadableStream<Uint8Array>) {
    this.reader = readable.getReader();
  }

  async readExactly(length: number): Promise<Uint8Array> {
    if (this.buffer.length === 0) {
      const { value, done } = await this.reader.read();
      if (done || !value) throw new Error("SOCKS5 upstream closed during handshake");
      if (value.length === length) return value;
      if (value.length > length) {
        this.buffer = value.subarray(length);
        return value.subarray(0, length);
      }
      this.buffer = value;
    }
    while (this.buffer.length < length) {
      const { value, done } = await this.reader.read();
      if (done || !value) throw new Error("SOCKS5 upstream closed during handshake");
      const merged = new Uint8Array(this.buffer.length + value.length);
      merged.set(this.buffer);
      merged.set(value, this.buffer.length);
      this.buffer = merged;
    }
    const result = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return result;
  }

  async pumpTo(
    websocket: Pick<WebSocket, "readyState" | "bufferedAmount" | "send" | "close">,
    isClosed: () => boolean,
    onActivity: () => void,
    responseHeader?: Uint8Array,
    options?: PumpBackpressureOptions,
  ): Promise<void> {
    const highWaterBytes = options?.highWaterBytes ?? WS_BACKPRESSURE_HIGH_WATER_BYTES;
    const maxBufferedBytes = options?.maxBufferedBytes ?? MAX_WS_BUFFERED_BYTES;
    const maxWaitMs = options?.maxWaitMs ?? WS_BACKPRESSURE_MAX_WAIT_MS;
    const sleep = options?.sleep ?? defaultSleep;
    let pendingHeader = responseHeader;

    const waitForBackpressure = async (): Promise<boolean> => {
      if (websocket.bufferedAmount < highWaterBytes) return true;
      let waitedMs = 0;
      let delayMs = 10;
      while (!isClosed() && websocket.readyState === WS_OPEN_READY_STATE && websocket.bufferedAmount >= highWaterBytes) {
        if (waitedMs >= maxWaitMs) {
          if (websocket.bufferedAmount > maxBufferedBytes) {
            try { websocket.close(1013, "client cannot keep up"); } catch { /* already closed */ }
            return false;
          }
          return true;
        }
        const step = Math.min(delayMs, maxWaitMs - waitedMs);
        await sleep(step);
        waitedMs += step;
        delayMs = Math.min(delayMs * 2, 50);
      }
      return !isClosed() && websocket.readyState === WS_OPEN_READY_STATE;
    };

    try {
      while (!isClosed()) {
        if (websocket.readyState !== WS_OPEN_READY_STATE) break;
        if (websocket.bufferedAmount >= highWaterBytes) {
          if (!(await waitForBackpressure())) break;
        }

        let chunk: Uint8Array | undefined;
        if (this.buffer.length) {
          chunk = this.buffer;
          this.buffer = new Uint8Array(0);
        } else {
          const { value, done } = await this.reader.read();
          if (done) break;
          chunk = value;
        }
        if (chunk?.length) {
          onActivity();
          if (websocket.readyState !== WS_OPEN_READY_STATE) break;
          if (websocket.bufferedAmount > maxBufferedBytes) {
            if (!(await waitForBackpressure())) break;
          }
          if (pendingHeader) {
            const combined = new Uint8Array(pendingHeader.length + chunk.length);
            combined.set(pendingHeader, 0);
            combined.set(chunk, pendingHeader.length);
            pendingHeader = undefined;
            websocket.send(combined);
          } else {
            websocket.send(chunk);
          }
        }
      }
    } finally {
      try { this.reader.releaseLock(); } catch { /* already released */ }
    }
  }
}

async function connectViaSocks5(
  env: Env,
  destinationHost: string,
  destinationPort: number,
): Promise<{ socket: ReturnType<typeof connect>; reader: SocketReader; writer: WritableStreamDefaultWriter<Uint8Array> }> {
  if (!env.H?.trim()) throw new Error("H is not configured");
  const proxyPort = Number(env.P || "1080");
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    throw new Error("P is invalid");
  }
  const username = env.SU || "";
  const password = env.SP || "";
  if ((username.length > 0) !== (password.length > 0)) {
    throw new Error("Both SU and SP must be set together");
  }
  const usernameBytes = UTF8_ENCODER.encode(username);
  const passwordBytes = UTF8_ENCODER.encode(password);
  if (usernameBytes.length > 255 || passwordBytes.length > 255) throw new Error("SOCKS5 credentials exceed protocol limits");

  const socket = connect({ hostname: env.H.trim(), port: proxyPort }, { allowHalfOpen: true });
  void socket.opened.catch(() => { /* connection failure surfaces via reader/writer */ });
  const writer = socket.writable.getWriter();
  const reader = new SocketReader(socket.readable);

  try {
    await writer.write(new Uint8Array(username ? [5, 2, 0, 2] : [5, 1, 0]));
    const greeting = await reader.readExactly(2);
    if (greeting[0] !== 5 || greeting[1] === 255) throw new Error("SOCKS5 proxy rejected authentication methods");
    if (greeting[1] === 2) {
      if (!username) throw new Error("SOCKS5 proxy requires username/password authentication");
      await writer.write(new Uint8Array([1, usernameBytes.length, ...usernameBytes, passwordBytes.length, ...passwordBytes]));
      const authReply = await reader.readExactly(2);
      if (authReply[0] !== 1 || authReply[1] !== 0) throw new Error("SOCKS5 authentication failed");
    } else if (greeting[1] !== 0) {
      throw new Error("SOCKS5 proxy selected an unsupported authentication method");
    }

    const address = encodeS5Address(destinationHost);
    await writer.write(new Uint8Array([
      5, 1, 0, ...address, (destinationPort >> 8) & 255, destinationPort & 255,
    ]));
    const reply = await reader.readExactly(4);
    if (reply[0] !== 5 || reply[2] !== 0) throw new Error("Invalid SOCKS5 CONNECT response");
    if (reply[1] !== 0) throw new Error("SOCKS5 CONNECT failed with code " + reply[1]);

    if (reply[3] === 1) await reader.readExactly(4);
    else if (reply[3] === 4) await reader.readExactly(16);
    else if (reply[3] === 3) {
      const length = await reader.readExactly(1);
      await reader.readExactly(length[0]);
    } else throw new Error("SOCKS5 returned an invalid bound address type");
    await reader.readExactly(2);

    return { socket, reader, writer };
  } catch (error) {
    try { await writer.abort(); } catch { /* already closed */ }
    try { await socket.close(); } catch { /* already closed */ }
    throw error;
  }
}


type UpstreamConnection = {
  socket: ReturnType<typeof connect>;
  reader: SocketReader;
  writer: WritableStreamDefaultWriter<Uint8Array>;
};

function connectDirect(host: string, port: number): UpstreamConnection {
  const socket = connect({ hostname: host, port }, { allowHalfOpen: true });
  // Pipeline the initial payload immediately without waiting for an extra JS
  // wakeup on socket.opened; dial errors surface cleanly via readable/writable.
  void socket.opened.catch(() => { /* handled via stream errors */ });
  return { socket, writer: socket.writable.getWriter(), reader: new SocketReader(socket.readable) };
}

let cachedRelayRaw: string | undefined;
let cachedRelayList: Array<{ hostname: string; port: number }> | undefined;

function relayCandidates(env: Env): Array<{ hostname: string; port: number }> {
  const raw = env.RE || "";
  if (raw === cachedRelayRaw && cachedRelayList) return cachedRelayList;
  const list = raw.split(/[;,\n]+/).map((item) => item.trim()).filter(Boolean).map((item) => {
    const match = /^([^:\s]+):(\d{1,5})$/.exec(item);
    if (!match) throw new Error("RE entries must use host:port format");
    const port = Number(match[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid relay port");
    return { hostname: match[1], port };
  });
  cachedRelayRaw = raw;
  cachedRelayList = list;
  return list;
}

function stableIndex(value: string, count: number): number {
  let hash = 2166136261;
  for (const char of value.toLowerCase()) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return (hash >>> 0) % count;
}

function isOutboundConfigured(env: Env): boolean {
  try {
    const mode = (env.OM || "direct").trim().toLowerCase();
    if (mode === "direct") return true;
    if (mode === "relay") return relayCandidates(env).length > 0;
    if (mode === "socks5") {
      if (!env.H?.trim()) return false;
      const port = Number(env.P || "1080");
      if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
      return (Boolean(env.SU) === Boolean(env.SP));
    }
    return false;
  } catch {
    return false;
  }
}

const relayCircuitBreakers = new CircuitBreakerRegistry({
  failureThreshold: 3,
  resetTimeoutMs: 30_000,
});

async function connectViaRelay(env: Env, destinationHost: string, destinationPort: number): Promise<UpstreamConnection> {
  if (destinationPort !== 443) throw new Error("SNI relay mode supports destination port 443 only");
  const candidates = relayCandidates(env);
  if (!candidates.length) throw new Error("RE is not configured");

  // Preserve deterministic preference, then fail over only among explicitly configured relays.
  const start = stableIndex(destinationHost, candidates.length);
  let lastError: unknown;
  let attempted = 0;
  for (let offset = 0; offset < candidates.length; offset++) {
    const endpoint = candidates[(start + offset) % candidates.length];
    const key = endpoint.hostname.toLowerCase() + ":" + endpoint.port;
    if (!relayCircuitBreakers.tryAcquire(key)) continue;
    attempted += 1;

    let socket: ReturnType<typeof connect> | undefined;
    try {
      socket = connect(endpoint, { allowHalfOpen: true });
      await socket.opened;
      relayCircuitBreakers.recordSuccess(key);
      return { socket, writer: socket.writable.getWriter(), reader: new SocketReader(socket.readable) };
    } catch (error) {
      lastError = error;
      relayCircuitBreakers.recordFailure(key);
      try { await socket?.close(); } catch { /* socket may not have opened */ }
    }
  }

  if (attempted === 0) throw new Error("All configured relay circuits are open");
  throw new Error("All configured relay endpoints failed: " +
    (lastError instanceof Error ? lastError.message : "upstream connection failed"));
}

async function handleWebSocket(request: Request, env: Env): Promise<Response> {
  const requestId = DEBUG_LOG ? crypto.randomUUID() : "";
  const startedAt = Date.now();
  const outboundMode = (env.OM || "direct").trim().toLowerCase();
  if (DEBUG_LOG) {
    debugLog("WS_REQUEST", {
      requestId,
      method: request.method,
      url: request.url,
      upgrade: request.headers.get("Upgrade"),
      hasProtocolHeader: Boolean(request.headers.get("Sec-WebSocket-Protocol")),
      proxyEnabled: env.PE === "true",
      uuidConfigured: Boolean(env.UUID),
      uuidFormatValid: Boolean(env.UUID && /^[0-9a-f]{8}-?[0-9a-f]{4}-?4?[0-9a-f]{3}-?[89ab]?[0-9a-f]{3}-?[0-9a-f]{12}$/i.test(env.UUID)),
      outboundMode,
      allowedPorts: env.AP || "(default)",
      allowedHostsConfigured: Boolean(env.AH?.trim()),
      outboundConfigured: isOutboundConfigured(env),
    });
  }

  if (request.method !== "GET") {
    if (DEBUG_LOG) debugLog("WS_REJECT", { requestId, stage: "HTTP_METHOD", method: request.method });
    return response("Not found", 404);
  }
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    if (DEBUG_LOG) debugLog("WS_REJECT", { requestId, stage: "UPGRADE_HEADER" });
    return response("Not found", 404);
  }
  if (env.PE !== "true") {
    if (DEBUG_LOG) debugLog("WS_REJECT", { requestId, stage: "PROXY_DISABLED" });
    return response("Not found", 404);
  }
  if (!env.UUID || !isOutboundConfigured(env)) {
    if (DEBUG_LOG) debugLog("WS_REJECT", { requestId, stage: "CONFIGURATION", uuidConfigured: Boolean(env.UUID), outboundConfigured: isOutboundConfigured(env) });
    return response("Not found", 404);
  }
  if (activeConnections >= MAX_CONNECTIONS_PER_ISOLATE) {
    if (DEBUG_LOG) debugLog("WS_REJECT", { requestId, stage: "CONNECTION_LIMIT" });
    return response("Service unavailable", 503, { "retry-after": "30" });
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  // Keep the synchronous binary-frame path on Workers whose default is Blob.
  // toBytes also supports Blob defensively if the runtime type is changed later.
  server.binaryType = "arraybuffer";
  server.accept({ allowHalfOpen: true });
  activeConnections += 1;

  let upstream: ReturnType<typeof connect> | undefined;
  let upstreamWriter: WritableStreamDefaultWriter<Uint8Array> | undefined;
  let initialized = false;
  let connecting = false;
  let closed = false;
  let messageIndex = 0;
  let pendingDecodes = 0;
  let decodeChain = Promise.resolve();
  let inFlightWriteBytes = 0;
  const pendingUpstream: Uint8Array[] = [];
  let pendingUpstreamBytes = 0;
  let lastActivityAt = startedAt;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  let lifetimeTimer: ReturnType<typeof setTimeout> | undefined;

  const markActivity = () => {
    lastActivityAt = Date.now();
  };

  const scheduleIdleCheck = (delayMs: number) => {
    idleTimer = setTimeout(() => {
      if (closed) return;
      const remaining = IDLE_CONNECTION_TIMEOUT_MS - (Date.now() - lastActivityAt);
      if (remaining > 0) {
        scheduleIdleCheck(remaining);
        return;
      }
      void closeBoth(1001, "idle timeout");
    }, delayMs);
  };

  const closeBoth = async (code = 1000, reason = "connection closed") => {
    if (closed) return;
    closed = true;
    pendingUpstream.length = 0;
    pendingUpstreamBytes = 0;
    if (idleTimer) clearTimeout(idleTimer);
    if (lifetimeTimer) clearTimeout(lifetimeTimer);
    activeConnections = Math.max(0, activeConnections - 1);
    if (DEBUG_LOG) {
      debugLog("WS_CLOSE", {
        requestId, code, reason, initialized,
        lifetimeMs: Date.now() - startedAt,
        messageCount: messageIndex,
        upstreamConnected: Boolean(upstream),
      });
    }
    try { server.close(code, reason.slice(0, 100)); } catch (error) {
      if (DEBUG_LOG) debugLog("WS_CLOSE_SERVER_ERROR", { requestId, ...debugError(error) });
    }
    if (upstreamWriter) {
      try { await upstreamWriter.abort(); } catch (error) {
        if (DEBUG_LOG) debugLog("UPSTREAM_WRITER_CLOSE_ERROR", { requestId, ...debugError(error) });
        try { upstreamWriter.releaseLock(); } catch { /* already released */ }
      }
    }
    try { await upstream?.close(); } catch (error) {
      if (DEBUG_LOG) debugLog("UPSTREAM_SOCKET_CLOSE_ERROR", { requestId, ...debugError(error) });
    }
  };

  const writeToUpstream = (chunk: Uint8Array) => {
    if (closed || !upstreamWriter) return;
    const len = chunk.byteLength;
    if (len === 0) return;
    inFlightWriteBytes += len;
    if (inFlightWriteBytes > MAX_UPSTREAM_QUEUED_BYTES) {
      void closeBoth(1013, "upstream cannot keep up");
      return;
    }
    void upstreamWriter.write(chunk).then(
      () => {
        inFlightWriteBytes = Math.max(0, inFlightWriteBytes - len);
      },
      (error: unknown) => {
        inFlightWriteBytes = Math.max(0, inFlightWriteBytes - len);
        if (DEBUG_LOG) debugLog("UPSTREAM_WRITE_FAILED", { requestId, ...debugError(error) });
        void closeBoth(1011, "upstream write failed");
      },
    );
  };

  const attachUpstream = (connection: UpstreamConnection, version: number, initialPayload: Uint8Array) => {
    if (closed) {
      void connection.writer.abort().catch(() => { /* already closed */ });
      void connection.socket.close().catch(() => { /* already closed */ });
      return;
    }
    upstream = connection.socket;
    upstreamWriter = connection.writer;
    initialized = true;
    connecting = false;

    if (initialPayload.byteLength) {
      writeToUpstream(initialPayload);
    }
    if (pendingUpstream.length) {
      for (const queued of pendingUpstream) {
        writeToUpstream(queued);
      }
      pendingUpstream.length = 0;
      pendingUpstreamBytes = 0;
    }

    const responseHeader = new Uint8Array([version, 0]);
    void connection.reader.pumpTo(server, () => closed, markActivity, responseHeader)
      .then(
        () => {
          if (DEBUG_LOG) debugLog("UPSTREAM_READ_PUMP_ENDED", { requestId });
          if (!closed) void closeBoth(1000, "upstream ended");
        },
        (error: unknown) => {
          if (DEBUG_LOG) debugLog("UPSTREAM_READ_PUMP_ERROR", { requestId, ...debugError(error) });
          void closeBoth(1011, "upstream read failed");
        },
      );
  };

  const handleDecodedFrame = (bytes: Uint8Array, currentMessage: number) => {
    if (closed) return;
    markActivity();

    if (bytes.byteLength > MAX_MESSAGE_BYTES) {
      if (DEBUG_LOG) debugLog("MESSAGE_SIZE_REJECTED", { requestId, messageIndex: currentMessage, byteLength: bytes.byteLength });
      void closeBoth(1008, "connection rejected");
      return;
    }

    if (initialized) {
      writeToUpstream(bytes);
      return;
    }

    if (connecting) {
      pendingUpstreamBytes += bytes.byteLength;
      if (pendingUpstreamBytes > MAX_UPSTREAM_QUEUED_BYTES) {
        void closeBoth(1013, "upstream cannot keep up");
        return;
      }
      pendingUpstream.push(bytes);
      return;
    }

    let stage = "VLESS_PARSE";
    const messageStartedAt = DEBUG_LOG ? Date.now() : 0;
    try {
      const parsed = parseV1Request(bytes, env.UUID);
      if (DEBUG_LOG) {
        debugLog("VLESS_PARSE_SUCCESS", {
          requestId, messageIndex: currentMessage,
          version: parsed.version, command: "TCP",
          destination: parsed.hostname, port: parsed.port,
          payloadLength: parsed.payload.byteLength,
          uuidMatched: true,
        });
      }

      stage = "PORT_CHECK";
      const ports = allowedPorts(env);
      if (!ports.has(parsed.port)) throw new Error("Destination port is not allowed");

      stage = "HOST_CHECK";
      const destinationHost = normalizeParsedDestination(parsed.hostname);
      if (!isDestinationHostAllowed(destinationHost, env.AH)) throw new Error("Destination host is not allowed");

      stage = "TCP_CONNECT";
      const connectStartedAt = DEBUG_LOG ? Date.now() : 0;
      if (DEBUG_LOG) {
        debugLog("TCP_CONNECT_START", { requestId, mode: outboundMode, destinationHost, destinationPort: parsed.port });
      }

      if (outboundMode === "direct") {
        const connection = connectDirect(destinationHost, parsed.port);
        attachUpstream(connection, parsed.version, parsed.payload);
        if (DEBUG_LOG) {
          debugLog("INITIALIZATION_SUCCESS", { requestId, durationMs: Date.now() - messageStartedAt });
        }
        return;
      }

      if (outboundMode !== "socks5" && outboundMode !== "relay") {
        throw new Error("OM must be direct, relay, or socks5");
      }

      connecting = true;
      const connectPromise = outboundMode === "socks5"
        ? connectViaSocks5(env, destinationHost, parsed.port)
        : connectViaRelay(env, destinationHost, parsed.port);

      void connectPromise.then(
        (connection) => {
          if (DEBUG_LOG) {
            debugLog("TCP_CONNECT_SUCCESS", {
              requestId, mode: outboundMode, destinationHost, destinationPort: parsed.port,
              connectDurationMs: Date.now() - connectStartedAt,
            });
          }
          attachUpstream(connection, parsed.version, parsed.payload);
          if (DEBUG_LOG) {
            debugLog("INITIALIZATION_SUCCESS", { requestId, durationMs: Date.now() - messageStartedAt });
          }
        },
        (error: unknown) => {
          connecting = false;
          if (DEBUG_LOG) {
            debugLog("MESSAGE_PROCESSING_FAILED", {
              requestId, messageIndex: currentMessage, stage: "TCP_CONNECT",
              durationMs: Date.now() - messageStartedAt,
              ...debugError(error),
            });
          }
          void closeBoth(1008, "connection rejected");
        },
      );
    } catch (error) {
      if (DEBUG_LOG) {
        debugLog("MESSAGE_PROCESSING_FAILED", {
          requestId, messageIndex: currentMessage, stage,
          durationMs: Date.now() - messageStartedAt,
          ...debugError(error),
        });
      }
      void closeBoth(1008, "connection rejected");
    }
  };

  scheduleIdleCheck(IDLE_CONNECTION_TIMEOUT_MS);
  lifetimeTimer = setTimeout(() => { void closeBoth(1001, "maximum lifetime reached"); }, MAX_CONNECTION_LIFETIME_MS);

  if (DEBUG_LOG) debugLog("WS_ACCEPTED", { requestId, readyState: server.readyState });

  server.addEventListener("message", (event: MessageEvent) => {
    if (closed) return;
    messageIndex += 1;
    const currentMessage = messageIndex;

    if (pendingDecodes === 0) {
      const syncBytes = toBytesSync(event.data);
      if (syncBytes) {
        handleDecodedFrame(syncBytes, currentMessage);
        return;
      }
    }

    pendingDecodes += 1;
    decodeChain = decodeChain.then(async () => {
      try {
        if (closed) return;
        const bytes = await toBytes(event.data);
        handleDecodedFrame(bytes, currentMessage);
      } catch (error) {
        if (DEBUG_LOG) {
          debugLog("MESSAGE_PROCESSING_FAILED", {
            requestId, messageIndex: currentMessage, stage: "MESSAGE_DECODE",
            ...debugError(error),
          });
        }
        await closeBoth(1008, "connection rejected");
      } finally {
        pendingDecodes -= 1;
      }
    });
  });

  server.addEventListener("close", (event: CloseEvent) => {
    if (DEBUG_LOG) debugLog("WS_PEER_CLOSE", { requestId, code: event.code, reason: event.reason, wasClean: event.wasClean });
    void closeBoth(1000, "client closed");
  });
  server.addEventListener("error", (event: Event) => {
    if (DEBUG_LOG) debugLog("WS_ERROR_EVENT", { requestId, eventType: event.type });
    void closeBoth(1011, "websocket error");
  });

  // Start processing 0-RTT early data immediately so the outbound TCP dial and
  // initial TLS ClientHello overlap with the 101 Switching Protocols response.
  const earlyData = decodeEarlyDataHeader(request.headers.get("Sec-WebSocket-Protocol"));
  if (earlyData) {
    messageIndex += 1;
    handleDecodedFrame(earlyData, messageIndex);
  }

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const publicSurfaceResponse = getPublicSurfaceResponse(request, env.HE);
    if (publicSurfaceResponse) return publicSurfaceResponse;
    return handleWebSocket(request, env);
  },
} satisfies ExportedHandler<Env>;
