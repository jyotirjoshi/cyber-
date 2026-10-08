import { describe, expect, it } from "vitest";

import { parseCustomFields } from "./custom-fields";

describe("custom field editor", () => {
  it("parses bounded scalar metadata", () => {
    expect(parseCustomFields('{"service_tier":"gold","regulated":true}')).toEqual({
      service_tier: "gold", regulated: true,
    });
  });

  it("rejects nested or sensitive fields before submission", () => {
    expect(() => parseCustomFields('{"api_key":"secret"}')).toThrow();
    expect(() => parseCustomFields('{"notes":"sk-abcdefghijklmnopqrstuvwxyz123456"}')).toThrow();
    expect(() => parseCustomFields('{"owner":{"name":"A"}}')).toThrow();
    expect(() => parseCustomFields('["not an object"]')).toThrow();
  });
});
