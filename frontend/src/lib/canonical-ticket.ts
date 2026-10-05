import type { CanonicalFindingStatus } from "./types";

/** Keep the UI aligned with the server's active-finding and deduplication rules. */
export function canCreateCanonicalTicket(
  status: CanonicalFindingStatus,
  tickets: ReadonlyArray<{ provider: string }>,
  permitted: boolean,
): boolean {
  return permitted
    && !["closed", "false_positive", "accepted_risk"].includes(status)
    && !tickets.some((ticket) => ticket.provider === "jira");
}
