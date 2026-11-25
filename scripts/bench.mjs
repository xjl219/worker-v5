#!/usr/bin/env node
/**
 * Zero-dependency latency & end-to-end VLESS benchmark for worker-v5.
 *
 * Examples:
 *   # Trace-only check (no UUID required; tests TCP/TLS/TTFB + Cloudflare colo):
 *   node scripts/bench.mjs --ips 188.114.97.3,188.114.99.3,104.26.1.1,104.21.1.1
 *
 *   # Full end-to-end VLESS benchmark comparing /ws vs /ws?ed=2048 (0-RTT):
 *   UUID=<your-uuid> node scripts/bench.mjs --ip 188.114.97.3 --runs 5
 *
 *   # PowerShell:
 *   $env:UUID="<your-uuid>"; node scripts/bench.mjs --ip 188.114.97.3 --runs 5
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import tls from "node:tls";
import { fileURLToPath } from "node:url";

const DEFAULT_HOST = "v5.xjl.dpdns.org";
const DEFAULT_PORT = 443;
const DEFAULT_TARGET = "cp.cloudflare.com:80";
const DEFAULT_TARGET_PATH = "/generate_204";
const DEFAULT_RUNS = 3;
const DEFAULT_TIMEOUT_MS = 5000;

export function parseUuidBytes(uuid) {
  const hex = String(uuid || "").trim().replaceAll("-", "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) {
    throw new Error("UUID must be a valid 32-hex-character UUID");
  }
  return Buffer.from(hex, "hex");
}

export function buildV1Request(uuid, targetHost, targetPort, payload = Buffer.alloc(0)) {
  const uuidBytes = parseUuidBytes(uuid);
  const hostBytes = Buffer.from(targetHost, "utf8");
  if (!hostBytes.length || hostBytes.length > 255) {
    throw new Error("Invalid target hostname");
  }
  const header = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + hostBytes.length);
  let offset = 0;
  header[offset++] = 0x00; // VLESS version 0
  uuidBytes.copy(header, offset);
  offset += 16;
  header[offset++] = 0x00; // addon length
  header[offset++] = 0x01; // TCP command
  header.writeUInt16BE(targetPort, offset);
  offset += 2;
  header[offset++] = 0x02; // domain address type
  header[offset++] = hostBytes.length;
  hostBytes.copy(header, offset);
  return payload.length ? Buffer.concat([header, payload]) : header;
}

export function encodeWsClientFrame(payload, opcode = 0x02) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const len = data.length;
  let headerLen = 2 + 4; // FIN/opcode + mask/len + 4-byte mask key
  if (len >= 126 && len <= 65535) headerLen += 2;
  else if (len > 65535) headerLen += 8;

  const frame = Buffer.alloc(headerLen + len);
  frame[0] = 0x80 | (opcode & 0x0f);
  let offset = 2;
  if (len < 126) {
    frame[1] = 0x80 | len;
  } else if (len <= 65535) {
    frame[1] = 0x80 | 126;
    frame.writeUInt16BE(len, offset);
    offset += 2;
  } else {
    frame[1] = 0x80 | 127;
    frame.writeBigUInt64BE(BigInt(len), offset);
    offset += 8;
  }

  const mask = crypto.randomBytes(4);
  mask.copy(frame, offset);
  offset += 4;
  for (let i = 0; i < len; i++) {
    frame[offset + i] = data[i] ^ mask[i & 3];
  }
  return frame;
}

export function parseWsServerFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let payloadLen = second & 0x7f;
    let pos = offset + 2;

    if (payloadLen === 126) {
      if (pos + 2 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(pos);
      pos += 2;
    } else if (payloadLen === 127) {
      if (pos + 8 > buffer.length) break;
      payloadLen = Number(buffer.readBigUInt64BE(pos));
      pos += 8;
    }

    const maskLen = masked ? 4 : 0;
    if (pos + maskLen + payloadLen > buffer.length) break;

    let payload = buffer.subarray(pos + maskLen, pos + maskLen + payloadLen);
    if (masked) {
      const mask = buffer.subarray(pos, pos + 4);
      const unmasked = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) unmasked[i] = payload[i] ^ mask[i & 3];
      payload = unmasked;
    }

    frames.push({ opcode, payload });
    offset = pos + maskLen + payloadLen;
  }
  return { frames, remaining: buffer.subarray(offset) };
}

function toBase64Url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function connectTlsTimed({ connectHost, port, servername, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    let tcpMs = null;
    let settled = false;

    const socket = tls.connect({
      host: connectHost,
      port,
      servername,
      ALPNProtocols: ["http/1.1"],
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`TLS connect timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    socket.once("connect", () => {
      tcpMs = performance.now() - startedAt;
    });

    socket.once("secureConnect", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const tlsDoneMs = performance.now() - startedAt;
      resolve({
        socket,
        startedAt,
        tcpMs: tcpMs ?? tlsDoneMs,
        tlsMs: tlsDoneMs,
      });
    });

    socket.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
  });
}

export async function probeTrace({ host, connectIp, port = DEFAULT_PORT, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  const { socket, startedAt, tcpMs, tlsMs } = await connectTlsTimed({
    connectHost: connectIp || host,
    port,
    servername: host,
    timeoutMs,
  });

  return new Promise((resolve, reject) => {
    let raw = Buffer.alloc(0);
    let ttfbMs = null;
    let settled = false;

    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) reject(err);
      else resolve(result);
    };

    const timer = setTimeout(() => finish(new Error(`Trace timed out after ${timeoutMs}ms`)), timeoutMs);

    socket.on("data", (chunk) => {
      if (ttfbMs === null) ttfbMs = performance.now() - startedAt;
      raw = Buffer.concat([raw, chunk]);
    });

    socket.once("end", () => {
      const text = raw.toString("utf8");
      const sep = text.indexOf("\r\n\r\n");
      const statusLine = text.split("\r\n")[0] || "";
      const statusMatch = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(statusLine);
      const httpStatus = statusMatch ? Number(statusMatch[1]) : 0;
      const body = sep >= 0 ? text.slice(sep + 4) : text;
      const fields = {};
      for (const line of body.split(/\r?\n/)) {
        const eq = line.indexOf("=");
        if (eq > 0) fields[line.slice(0, eq)] = line.slice(eq + 1);
      }
      if (httpStatus !== 200 || !fields.colo) {
        finish(new Error(`Unexpected trace response (HTTP ${httpStatus || "?"}): ${body.trim().slice(0, 80)}`));
        return;
      }
      finish(null, {
        ip: connectIp || host,
        colo: fields.colo,
        loc: fields.loc || "-",
        clientIp: fields.ip || "-",
        tlsVersion: fields.tls || "-",
        tcpMs,
        tlsMs,
        ttfbMs: ttfbMs ?? (performance.now() - startedAt),
      });
    });

    socket.once("error", (err) => finish(err));

    socket.write(
      `GET /cdn-cgi/trace HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `User-Agent: worker-v5-bench/1.0\r\n` +
      `Connection: close\r\n\r\n`,
    );
  });
}

export async function benchVlessOnce({
  host,
  connectIp,
  port = DEFAULT_PORT,
  uuid,
  targetHost,
  targetPort,
  targetPath = DEFAULT_TARGET_PATH,
  earlyData = false,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const httpPayload = Buffer.from(
    `GET ${targetPath} HTTP/1.1\r\n` +
    `Host: ${targetHost}\r\n` +
    `User-Agent: worker-v5-bench/1.0\r\n` +
    `Connection: close\r\n\r\n`,
    "utf8",
  );
  const vlessFrame = buildV1Request(uuid, targetHost, targetPort, httpPayload);

  const { socket, startedAt, tcpMs, tlsMs } = await connectTlsTimed({
    connectHost: connectIp || host,
    port,
    servername: host,
    timeoutMs,
  });

  return new Promise((resolve, reject) => {
    let settled = false;
    let upgraded = false;
    let wsUpgradeMs = null;
    let vlessSentAt = null;
    let headerBuf = Buffer.alloc(0);
    let wsBuf = Buffer.alloc(0);
    let vlessResponseChecked = false;
    let downstream = Buffer.alloc(0);

    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) reject(err);
      else resolve(result);
    };

    const timer = setTimeout(() => finish(new Error(`VLESS benchmark timed out after ${timeoutMs}ms`)), timeoutMs);

    const handleWsBytes = (incoming) => {
      wsBuf = Buffer.concat([wsBuf, incoming]);
      const { frames, remaining } = parseWsServerFrames(wsBuf);
      wsBuf = remaining;

      for (const frame of frames) {
        if (frame.opcode === 0x08) {
          const code = frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : 1005;
          const reason = frame.payload.length > 2 ? frame.payload.subarray(2).toString("utf8") : "";
          finish(new Error(`WebSocket closed before target response (code=${code}${reason ? `, reason=${reason}` : ""})`));
          return;
        }
        if (frame.opcode === 0x09) {
          socket.write(encodeWsClientFrame(frame.payload, 0x0a)); // Pong
          continue;
        }
        if (frame.opcode !== 0x02 && frame.opcode !== 0x00) continue;

        let chunk = frame.payload;
        if (!vlessResponseChecked) {
          if (chunk.length < 2) {
            downstream = Buffer.concat([downstream, chunk]);
            if (downstream.length < 2) continue;
            chunk = downstream;
            downstream = Buffer.alloc(0);
          }
          if (chunk[0] !== 0x00) {
            finish(new Error(`Unexpected VLESS response version byte: 0x${chunk[0].toString(16)}`));
            return;
          }
          const addonLen = chunk[1];
          if (chunk.length < 2 + addonLen) {
            finish(new Error("Incomplete VLESS response addon"));
            return;
          }
          vlessResponseChecked = true;
          chunk = chunk.subarray(2 + addonLen);
        }

        if (chunk.length) {
          downstream = Buffer.concat([downstream, chunk]);
          const lineEnd = downstream.indexOf("\r\n");
          if (lineEnd >= 0) {
            const now = performance.now();
            const statusLine = downstream.subarray(0, lineEnd).toString("utf8");
            const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(statusLine);
            finish(null, {
              tcpMs,
              tlsMs,
              wsUpgradeMs: wsUpgradeMs ?? (now - startedAt),
              vlessRttMs: vlessSentAt !== null ? now - vlessSentAt : now - startedAt,
              totalMs: now - startedAt,
              targetStatus: match ? Number(match[1]) : 0,
              statusLine,
            });
            return;
          }
        }
      }
    };

    socket.on("data", (chunk) => {
      if (!upgraded) {
        headerBuf = Buffer.concat([headerBuf, chunk]);
        const sep = headerBuf.indexOf("\r\n\r\n");
        if (sep < 0) return;

        const headerText = headerBuf.subarray(0, sep).toString("utf8");
        const statusLine = headerText.split("\r\n")[0] || "";
        if (!/^HTTP\/1\.1\s+101\b/.test(statusLine)) {
          finish(new Error(`WebSocket upgrade failed: ${statusLine}`));
          return;
        }

        upgraded = true;
        wsUpgradeMs = performance.now() - startedAt;
        if (!earlyData) {
          vlessSentAt = performance.now();
          socket.write(encodeWsClientFrame(vlessFrame, 0x02));
        }

        const leftover = headerBuf.subarray(sep + 4);
        headerBuf = Buffer.alloc(0);
        if (leftover.length) handleWsBytes(leftover);
        return;
      }

      handleWsBytes(chunk);
    });

    socket.once("close", () => {
      if (!settled) finish(new Error("Connection closed before receiving target HTTP response"));
    });
    socket.once("error", (err) => finish(err));

    const wsKey = crypto.randomBytes(16).toString("base64");
    const wsPath = earlyData ? "/ws?ed=2048" : "/ws";
    const lines = [
      `GET ${wsPath} HTTP/1.1`,
      `Host: ${host}`,
      `Upgrade: websocket`,
      `Connection: Upgrade`,
      `Sec-WebSocket-Key: ${wsKey}`,
      `Sec-WebSocket-Version: 13`,
      `User-Agent: worker-v5-bench/1.0`,
    ];
    if (earlyData) {
      lines.push(`Sec-WebSocket-Protocol: ${toBase64Url(vlessFrame)}`);
      vlessSentAt = performance.now();
    }
    socket.write(lines.join("\r\n") + "\r\n\r\n");
  });
}

function loadUuidFromLocalFile() {
  const p = path.resolve(process.cwd(), ".wrangler", "proxy-uuid.txt");
  try {
    if (fs.existsSync(p)) {
      const val = fs.readFileSync(p, "utf8").trim();
      if (val) return val;
    }
  } catch { /* ignore */ }
  return "";
}

function parseArgs(argv) {
  const opts = {
    host: DEFAULT_HOST,
    port: DEFAULT_PORT,
    ips: [],
    target: DEFAULT_TARGET,
    targetPath: DEFAULT_TARGET_PATH,
    runs: DEFAULT_RUNS,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    traceOnly: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--host") opts.host = argv[++i];
    else if (arg === "--port") opts.port = Number(argv[++i]);
    else if (arg === "--ip") opts.ips.push(argv[++i]);
    else if (arg === "--ips") opts.ips.push(...argv[++i].split(",").map((s) => s.trim()).filter(Boolean));
    else if (arg === "--target") opts.target = argv[++i];
    else if (arg === "--target-path") opts.targetPath = argv[++i];
    else if (arg === "--runs") opts.runs = Number(argv[++i]);
    else if (arg === "--timeout") opts.timeoutMs = Number(argv[++i]);
    else if (arg === "--trace-only") opts.traceOnly = true;
    else if (arg === "-h" || arg === "--help") {
      console.log(`Usage: node scripts/bench.mjs [options]
  --host <domain>       Worker hostname (default: ${DEFAULT_HOST})
  --port <port>         Worker TLS port (default: ${DEFAULT_PORT})
  --ip <ip>             Single Cloudflare edge IP to test
  --ips <ip1,ip2,...>   Comma-separated Cloudflare edge IPs to test
  --target <host:port>  Target HTTP endpoint through VLESS (default: ${DEFAULT_TARGET})
  --target-path <path>  Target HTTP path (default: ${DEFAULT_TARGET_PATH})
  --runs <n>            Iterations per mode (default: ${DEFAULT_RUNS})
  --timeout <ms>        Timeout per attempt in ms (default: ${DEFAULT_TIMEOUT_MS})
  --trace-only          Skip VLESS test even if UUID is set

Environment:
  UUID                  VLESS proxy UUID (or auto-loaded from .wrangler/proxy-uuid.txt)`);
      process.exit(0);
    }
  }
  return opts;
}

function fmt(ms) {
  return `${ms.toFixed(1)}ms`;
}

function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const avg = sorted.reduce((acc, v) => acc + v, 0) / sorted.length;
  return { min: sorted[0], avg, max: sorted[sorted.length - 1] };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const [targetHost, rawTargetPort] = opts.target.split(":");
  const targetPort = Number(rawTargetPort || "80");
  const uuid = opts.traceOnly ? "" : (process.env.UUID?.trim() || loadUuidFromLocalFile());
  const targets = opts.ips.length ? opts.ips : [opts.host];

  console.log(`Worker: https://${opts.host}:${opts.port} | Runs: ${opts.runs} | Mode: ${uuid ? "Trace + VLESS (/ws vs 0-RTT)" : "Trace only (set UUID env for VLESS)"}`);
  console.log("");

  const traceRows = [];
  for (const connectIp of targets) {
    try {
      const res = await probeTrace({ host: opts.host, connectIp, port: opts.port, timeoutMs: opts.timeoutMs });
      traceRows.push(res);
    } catch (err) {
      console.log(`[TRACE] ${connectIp.padEnd(16)} FAILED: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  traceRows.sort((a, b) => a.ttfbMs - b.ttfbMs);
  if (traceRows.length) {
    console.log("== Stage 1: Direct Edge /cdn-cgi/trace ==");
    console.log("IP/Host          Colo  Loc  TCP       TLS       TTFB      TLSVer");
    for (const r of traceRows) {
      console.log(
        `${r.ip.padEnd(16)} ${r.colo.padEnd(5)} ${r.loc.padEnd(4)} ` +
        `${fmt(r.tcpMs).padEnd(9)} ${fmt(r.tlsMs).padEnd(9)} ${fmt(r.ttfbMs).padEnd(9)} ${r.tlsVersion}`,
      );
    }
    console.log("");
  }

  if (!uuid) {
    console.log("Tip: Set UUID env var to benchmark full end-to-end VLESS (/ws vs /ws?ed=2048):");
    console.log(`  PowerShell: $env:UUID="<your-uuid>"; node scripts/bench.mjs --ip ${traceRows[0]?.ip || "188.114.97.3"}`);
    console.log(`  Bash:       UUID="<your-uuid>" node scripts/bench.mjs --ip ${traceRows[0]?.ip || "188.114.97.3"}`);
    return;
  }

  console.log(`== Stage 2: End-to-End VLESS (${opts.target}${opts.targetPath}) ==`);
  for (const row of traceRows) {
    console.log(`\nTarget Edge: ${row.ip} (${row.colo})`);
    for (const earlyData of [false, true]) {
      const label = earlyData ? "0-RTT (/ws?ed=2048)" : "Normal (/ws)       ";
      const ok = [];
      let lastErr = null;
      for (let i = 0; i < opts.runs; i++) {
        try {
          ok.push(await benchVlessOnce({
            host: opts.host,
            connectIp: row.ip,
            port: opts.port,
            uuid,
            targetHost,
            targetPort,
            targetPath: opts.targetPath,
            earlyData,
            timeoutMs: opts.timeoutMs,
          }));
        } catch (err) {
          lastErr = err instanceof Error ? err.message : String(err);
        }
      }
      if (!ok.length) {
        console.log(`  ${label} -> FAILED (${lastErr})`);
        continue;
      }
      const wsSum = summarize(ok.map((x) => x.wsUpgradeMs));
      const vlessSum = summarize(ok.map((x) => x.vlessRttMs));
      const totalSum = summarize(ok.map((x) => x.totalMs));
      const statuses = [...new Set(ok.map((x) => x.targetStatus))].join(",");
      console.log(
        `  ${label} -> ok ${ok.length}/${opts.runs} | HTTP ${statuses} | ` +
        `WS101 avg ${fmt(wsSum.avg)} | VLESS->Target avg ${fmt(vlessSum.avg)} | ` +
        `Total min/avg/max ${fmt(totalSum.min)} / ${fmt(totalSum.avg)} / ${fmt(totalSum.max)}`,
      );
    }
  }
}

const isEntrypoint = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  main().catch((err) => {
    console.error("Benchmark failed:", err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
