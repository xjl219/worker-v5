import { connect } from "cloudflare:sockets";
import { parseV1Request, encodeS5Address } from "./v1-s5";
import { normalizeDestinationHostname, parseAllowedHosts } from "./security";
import { CircuitBreakerRegistry } from "./circuit-breaker";
import { getPublicSurfaceResponse } from "./public-surface";

interface Env {
  UUID: string;
  ALLOWED_PORTS?: string;
  ALLOWED_HOSTS?: string;
  PROXY_ENABLED?: string;
  HEALTH_ENABLED?: string;
  OUTBOUND_MODE?: string;
  RELAY_ENDPOINTS?: string;
  SOCKS5_HOST?: string;
  SOCKS5_PORT?: string;
  SOCKS5_USERNAME?: string;
  SOCKS5_PASSWORD?: string;
}

const DEFAULT_ALLOWED_PORTS = [80, 443, 8080, 8443, 2053, 2083, 2087, 2096];
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
const MAX_WS_BUFFERED_BYTES = 4 * 1024 * 1024;
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


function toBytes(data: unknown): Uint8Array {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new Error("Only binary WebSocket messages are supported");
}

function allowedHosts(env: Env): Set<string> {
  return parseAllowedHosts(env.ALLOWED_HOSTS);
}

function hasValidAllowedHosts(env: Env): boolean {
  try {
    return allowedHosts(env).size > 0;
  } catch {
    return false;
  }
}

function allowedPorts(env: Env): Set<number> {
  const raw = env.ALLOWED_PORTS?.trim();
  if (!raw) return new Set(DEFAULT_ALLOWED_PORTS);
  const ports = raw.split(",").map((value) => Number(value.trim()));
  if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error("ALLOWED_PORTS contains an invalid port");
  }
  return new Set(ports);
}

class SocketReader {
  private buffer = new Uint8Array(0);
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;

  constructor(readable: ReadableStream<Uint8Array>) {
    this.reader = readable.getReader();
  }

  async readExactly(length: number): Promise<Uint8Array> {
    while (this.buffer.length < length) {
      const { value, done } = await this.reader.read();
      if (done || !value) throw new Error("SOCKS5 upstream closed during handshake");
      const merged = new Uint8Array(this.buffer.length + value.length);
      merged.set(this.buffer);
      merged.set(value, this.buffer.length);
      this.buffer = merged;
    }
    const result = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return result;
  }

  async pumpTo(websocket: WebSocket, isClosed: () => boolean): Promise<void> {
    try {
      while (!isClosed()) {
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
          if (websocket.readyState !== WebSocket.OPEN) break;
          if (websocket.bufferedAmount > MAX_WS_BUFFERED_BYTES) {
            try { websocket.close(1013, "client cannot keep up"); } catch { /* already closed */ }
            break;
          }
          websocket.send(chunk);
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
  if (!env.SOCKS5_HOST?.trim()) throw new Error("SOCKS5_HOST is not configured");
  const proxyPort = Number(env.SOCKS5_PORT || "1080");
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    throw new Error("SOCKS5_PORT is invalid");
  }
  const username = env.SOCKS5_USERNAME || "";
  const password = env.SOCKS5_PASSWORD || "";
  if ((username.length > 0) !== (password.length > 0)) {
    throw new Error("Both SOCKS5_USERNAME and SOCKS5_PASSWORD must be set together");
  }
  const usernameBytes = new TextEncoder().encode(username);
  const passwordBytes = new TextEncoder().encode(password);
  if (usernameBytes.length > 255 || passwordBytes.length > 255) throw new Error("SOCKS5 credentials exceed protocol limits");

  const socket = connect({ hostname: env.SOCKS5_HOST.trim(), port: proxyPort }, { allowHalfOpen: true });
  await socket.opened;
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
    try { await writer.close(); } catch { /* already closed */ }
    try { await socket.close(); } catch { /* already closed */ }
    throw error;
  }
}


type UpstreamConnection = {
  socket: ReturnType<typeof connect>;
  reader: SocketReader;
  writer: WritableStreamDefaultWriter<Uint8Array>;
};

async function connectDirect(host: string, port: number): Promise<UpstreamConnection> {
  const socket = connect({ hostname: host, port }, { allowHalfOpen: true });
  await socket.opened;
  return { socket, writer: socket.writable.getWriter(), reader: new SocketReader(socket.readable) };
}

function relayCandidates(env: Env): Array<{ hostname: string; port: number }> {
  return (env.RELAY_ENDPOINTS || "").split(/[;,\n]+/).map((item) => item.trim()).filter(Boolean).map((item) => {
    const match = /^([^:\s]+):(\d{1,5})$/.exec(item);
    if (!match) throw new Error("RELAY_ENDPOINTS entries must use host:port format");
    const port = Number(match[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid relay port");
    return { hostname: match[1], port };
  });
}

function stableIndex(value: string, count: number): number {
  let hash = 2166136261;
  for (const char of value.toLowerCase()) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return (hash >>> 0) % count;
}

function isOutboundConfigured(env: Env): boolean {
  try {
    const mode = (env.OUTBOUND_MODE || "direct").trim().toLowerCase();
    if (mode === "direct") return true;
    if (mode === "relay") return relayCandidates(env).length > 0;
    if (mode === "socks5") {
      if (!env.SOCKS5_HOST?.trim()) return false;
      const port = Number(env.SOCKS5_PORT || "1080");
      if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
      return (Boolean(env.SOCKS5_USERNAME) === Boolean(env.SOCKS5_PASSWORD));
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
  if (!candidates.length) throw new Error("RELAY_ENDPOINTS is not configured");

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

async function connectOutbound(env: Env, host: string, port: number): Promise<UpstreamConnection> {
  const mode = (env.OUTBOUND_MODE || "direct").trim().toLowerCase();
  if (mode === "direct") return connectDirect(host, port);
  if (mode === "socks5") return connectViaSocks5(env, host, port);
  if (mode === "relay") return connectViaRelay(env, host, port);
  throw new Error("OUTBOUND_MODE must be direct, relay, or socks5");
}

async function handleWebSocket(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return response("Not found", 404);
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return response("Not found", 404);
  }
  if (env.PROXY_ENABLED !== "true") return response("Not found", 404);
  if (!env.UUID || !isOutboundConfigured(env) || !hasValidAllowedHosts(env)) {
    return response("Not found", 404);
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept({ allowHalfOpen: true });

  let upstream: ReturnType<typeof connect> | undefined;
  let upstreamWriter: WritableStreamDefaultWriter<Uint8Array> | undefined;
  let initialized = false;
  let closed = false;
  let messageChain = Promise.resolve();

  const closeBoth = async (code = 1000, reason = "connection closed") => {
    if (closed) return;
    closed = true;
    try { server.close(code, reason.slice(0, 100)); } catch { /* already closed */ }
    try { await upstreamWriter?.close(); } catch { /* already closed */ }
    try { await upstream?.close(); } catch { /* already closed */ }
  };

  server.addEventListener("message", (event: MessageEvent) => {
    messageChain = messageChain.then(async () => {
      if (closed) return;
      const bytes = toBytes(event.data);
      if (bytes.byteLength > MAX_MESSAGE_BYTES) throw new Error("WebSocket message exceeds 8 MiB limit");

      if (!initialized) {
        const parsed = parseV1Request(bytes, env.UUID);
        if (!allowedPorts(env).has(parsed.port)) throw new Error("Destination port is not allowed");
        const destinationHost = normalizeDestinationHostname(parsed.hostname);
        if (!allowedHosts(env).has(destinationHost)) throw new Error("Destination host is not allowed");

        const connection = await connectOutbound(env, parsed.hostname, parsed.port);
        upstream = connection.socket;
        upstreamWriter = connection.writer;
        initialized = true;
        server.send(new Uint8Array([parsed.version, 0]));
        if (parsed.payload.byteLength) await upstreamWriter.write(parsed.payload);
        void connection.reader.pumpTo(server, () => closed)
          .finally(() => { if (!closed) void closeBoth(1000, "upstream ended"); })
          .catch(() => closeBoth(1011, "upstream read failed"));
        return;
      }

      if (!upstreamWriter) throw new Error("Upstream is not ready");
      await upstreamWriter.write(bytes);
    }).catch(async (error: unknown) => {
      // Never disclose whether authentication, destination policy, or upstream setup failed.
      await closeBoth(1008, "connection rejected");
    });
  });

  server.addEventListener("close", () => { void closeBoth(); });
  server.addEventListener("error", () => { void closeBoth(1011, "websocket error"); });

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const publicSurfaceResponse = getPublicSurfaceResponse(request, env.HEALTH_ENABLED);
    if (publicSurfaceResponse) return publicSurfaceResponse;
    return handleWebSocket(request, env);
  },
} satisfies ExportedHandler<Env>;
