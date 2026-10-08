export type CustomFields = Record<string, string | number | boolean>;

const namePattern = /^[a-z][a-z0-9_]{0,39}$/;
const sensitiveNames = ["secret", "password", "token", "credential", "api_key", "private_key"];
const tokenValue = /(?:sk-|ghp_|glpat-|AQ\.)[a-z0-9_-]{12,}/i;

export function parseCustomFields(text: string): CustomFields {
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Custom fields must be a JSON object.");
  }
  const entries = Object.entries(parsed);
  if (entries.length > 20) throw new Error("Use at most 20 custom fields.");
  const fields: CustomFields = {};
  for (const [name, value] of entries) {
    if (!namePattern.test(name) || sensitiveNames.some((part) => name.includes(part))) {
      throw new Error(`Invalid or sensitive custom field name: ${name}`);
    }
    if (typeof value === "string") {
      if (value.length > 200 || /[\x00-\x1f]/.test(value)) {
        throw new Error(`Custom field ${name} must be at most 200 printable characters.`);
      }
      if (tokenValue.test(value)) throw new Error("Custom fields must not contain credentials.");
    } else if (typeof value === "number") {
      if (!Number.isFinite(value) || Math.abs(value) > 1_000_000_000_000) {
        throw new Error(`Custom field ${name} is out of range.`);
      }
    } else if (typeof value !== "boolean") {
      throw new Error(`Custom field ${name} must be text, a number, or true/false.`);
    }
    fields[name] = value;
  }
  return fields;
}
