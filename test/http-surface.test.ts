import { describe, expect, it } from "vitest";
import { getPublicSurfaceResponse } from "../src/index";

function probe(path: string, options: RequestInit = {}, healthEnabled?: string): Response | null {
  return getPublicSurfaceResponse(new Request("https://worker.example" + path, options), healthEnabled);
}

describe("public HTTP surface", () => {
  it("hides health by default", async () => {
    const response = probe("/health");
    expect(response?.status).toBe(404);
    expect(await response?.text()).toBe("Not found");
  });

  it("exposes only a generic liveness response when health is explicitly enabled", async () => {
    const response = probe("/health", {}, "true");
    expect(response?.status).toBe(200);
    expect(await response?.json()).toEqual({ ok: true });
  });

  it("returns the same not-found response for root, unknown, and sensitive paths", async () => {
    for (const path of ["/", "/admin", "/robots.txt", "/.env", "/.git/config"]) {
      const response = probe(path);
      expect(response?.status).toBe(404);
      expect(await response?.text()).toBe("Not found");
    }
  });

  it("does not reveal the WebSocket route to ordinary HTTP probes", async () => {
    const response = probe("/ws");
    expect(response?.status).toBe(404);
    expect(await response?.text()).toBe("Not found");
  });

  it("passes only a real WebSocket upgrade on the proxy path to the handler", () => {
    const response = probe("/ws", { headers: { Upgrade: "websocket" } });
    expect(response).toBeNull();
  });

  it("normalizes unsupported methods to the same not-found response", async () => {
    const response = probe("/ws", { method: "POST" });
    expect(response?.status).toBe(404);
    expect(await response?.text()).toBe("Not found");
  });
});
