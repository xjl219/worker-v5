import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateUuid(value) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value.trim())) {
    throw new Error("PROXY_UUID/UUID must be a canonical UUID");
  }
  return value.trim();
}

export function parseSecretNames(output) {
  let parsed;
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new Error("Unable to parse Wrangler secret list output; refusing to rotate the proxy UUID");
  }
  const entries = Array.isArray(parsed) ? parsed : parsed?.secrets;
  if (!Array.isArray(entries)) {
    throw new Error("Unexpected Wrangler secret list format; refusing to rotate the proxy UUID");
  }
  return new Set(entries.map((entry) => entry?.name).filter((name) => typeof name === "string"));
}

export function resolveDeploymentUuid({ configuredUuid, secretNames, generatedUuid = randomUUID() }) {
  if (configuredUuid !== undefined && configuredUuid !== "") {
    return { action: "set", uuid: validateUuid(configuredUuid) };
  }
  if (secretNames.has("UUID")) return { action: "reuse", uuid: null };
  return { action: "set", uuid: validateUuid(generatedUuid) };
}

function runWrangler(args, input) {
  const command = process.platform === "win32" ? "npx.cmd" : "npx";
  const result = spawnSync(command, ["wrangler", ...args], {
    encoding: "utf8",
    input,
    shell: process.platform === "win32",
    stdio: input === undefined ? ["inherit", "pipe", "inherit"] : ["pipe", "inherit", "inherit"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`wrangler ${args[0]} failed with exit code ${result.status ?? "unknown"}`);
  }
  return result.stdout ?? "";
}

function listRemoteSecretNames() {
  const command = process.platform === "win32" ? "npx.cmd" : "npx";
  const result = spawnSync(command, ["wrangler", "secret", "list", "--format", "json"], {
    encoding: "utf8",
    shell: process.platform === "win32",
    stdio: ["inherit", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status === 0) return parseSecretNames(result.stdout ?? "");

  const diagnostic = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.toLowerCase();
  // A missing Worker is expected on first deployment. Other failures (especially
  // authentication/permission errors) must stop instead of risking credential rotation.
  if (diagnostic.includes("worker not found") || diagnostic.includes("script not found") ||
      diagnostic.includes("worker does not exist") || diagnostic.includes("script does not exist") || diagnostic.includes("10007")) {
    return null;
  }
  throw new Error("Unable to inspect Cloudflare Worker secrets; refusing to rotate the proxy UUID");
}

function readSavedUuid() {
  const savedPath = join(process.cwd(), ".wrangler", "proxy-uuid.txt");
  if (!existsSync(savedPath)) return undefined;
  return validateUuid(readFileSync(savedPath, "utf8"));
}

export function saveGeneratedUuid(uuid, rootDirectory = process.cwd()) {
  const directory = join(rootDirectory, ".wrangler");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(join(directory, "proxy-uuid.txt"), uuid + String.fromCharCode(10), { mode: 0o600 });
}

async function main() {
  const configuredUuid = process.env.PROXY_UUID || process.env.UUID;
  let secretNames = new Set();
  let remoteWorkerExists = true;
  let savedUuid;

  if (configuredUuid === undefined || configuredUuid === "") {
    const remoteSecrets = listRemoteSecretNames();
    remoteWorkerExists = remoteSecrets !== null;
    if (remoteWorkerExists) secretNames = remoteSecrets;
    savedUuid = readSavedUuid();
  }

  const decision = resolveDeploymentUuid({
    configuredUuid,
    secretNames,
    generatedUuid: savedUuid ?? randomUUID(),
  });
  if (decision.action === "reuse") {
    process.stdout.write("Reusing the existing Cloudflare UUID secret.\n");
    // Keep variables managed in Cloudflare Dashboard (including PROXY_ENABLED)
    // instead of replacing them with the checked-in Wrangler configuration.
    runWrangler(["deploy", "--keep-vars"]);
    return;
  }

  // Persist a newly generated credential before deployment so a failed deployment can
  // be retried with the same UUID. The file is ignored by Git and has restrictive permissions.
  if (!configuredUuid && !savedUuid) saveGeneratedUuid(decision.uuid);

  // Wrangler consumes secrets-file during the deployment itself. Keep the short-lived
  // file outside the repository, restrict its permissions, and always remove it.
  const tempDirectory = mkdtempSync(join(tmpdir(), "worker-v5-"));
  const secretsFile = join(tempDirectory, "secrets.json");
  try {
    writeFileSync(secretsFile, JSON.stringify({ UUID: decision.uuid }), { mode: 0o600, flag: "wx" });
    runWrangler(["deploy", "--keep-vars", "--secrets-file", secretsFile]);
  } finally {
    rmSync(tempDirectory, { recursive: true, force: true });
  }
  process.stdout.write((configuredUuid ? "Deployed with the supplied UUID secret." : "Generated and deployed a new UUID secret.") + String.fromCharCode(10));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Secure deployment stopped: ${error.message}\n`);
    process.exitCode = 1;
  });
}
