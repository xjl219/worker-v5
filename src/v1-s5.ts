import { normalizeDestinationHostname } from "./security";

export type ParsedRequest = {
  version: number;
  hostname: string;
  port: number;
  payload: Uint8Array;
};

function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replaceAll("-", "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("UUID must be a valid 32-character UUID");
  return Uint8Array.from(hex.match(/.{2}/g)!, (part) => Number.parseInt(part, 16));
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
    const decodedHostname = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data.subarray(addressOffset, addressOffset + addressLength));
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
  return { version, hostname, port, payload: data.slice(payloadOffset) };
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
  const domain = new TextEncoder().encode(host);
  if (!domain.length || domain.length > 255) throw new Error("Invalid S5 destination hostname");
  return new Uint8Array([3, domain.length, ...domain]);
}
