export type UuidDecision =
  | { action: "set"; uuid: string }
  | { action: "reuse"; uuid: null };

export function validateUuid(value: unknown): string;
export function parseSecretNames(output: string): Set<string>;
export function resolveDeploymentUuid(options: {
  configuredUuid: string | undefined;
  secretNames: Set<string>;
  generatedUuid?: string;
}): UuidDecision;
export function saveGeneratedUuid(uuid: string, rootDirectory?: string): void;
