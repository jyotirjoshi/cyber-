import { describe, expect, it } from "vitest";

import { apiOrigin, websocketOrigin } from "./api";

describe("Firebase same-origin routing", () => {
  it("uses the current origin for API paths when no override is configured", () => {
    expect(apiOrigin("")).toBe("");
  });

  it("derives a secure websocket origin from an HTTPS public page", () => {
    expect(websocketOrigin({ protocol: "https:", host: "cynux.web.app" }, "")).toBe(
      "wss://cynux.web.app",
    );
  });

  it("preserves explicit development origins without a trailing slash", () => {
    expect(apiOrigin("http://localhost:8000/")).toBe("http://localhost:8000");
    expect(
      websocketOrigin({ protocol: "https:", host: "ignored.example" }, "ws://localhost:8000/"),
    ).toBe("ws://localhost:8000");
  });
});

