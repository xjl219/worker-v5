export function connect(): never {
  throw new Error("Cloudflare sockets are unavailable in the Vitest environment");
}
