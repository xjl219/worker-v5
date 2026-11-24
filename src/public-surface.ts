const SECURITY_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

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
