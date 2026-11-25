export function parseUuidBytes(uuid: string): Buffer;
export function buildV1Request(
  uuid: string,
  targetHost: string,
  targetPort: number,
  payload?: Buffer,
): Buffer;
export function encodeWsClientFrame(payload: Uint8Array | Buffer, opcode?: number): Buffer;
export function parseWsServerFrames(buffer: Buffer): {
  frames: Array<{ opcode: number; payload: Buffer }>;
  remaining: Buffer;
};
