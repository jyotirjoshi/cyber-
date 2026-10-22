import type { PlatformSearchResultOut } from "./types";

const ORDER: PlatformSearchResultOut["kind"][] = ["asset", "finding", "case", "ticket", "agent", "report"];

export function groupSearchResults(results: PlatformSearchResultOut[]) {
  return ORDER
    .map((kind) => [kind, results.filter((result) => result.kind === kind)] as const)
    .filter(([, items]) => items.length > 0);
}
