export type IntegrationTestResult = {
  healthy: boolean;
  detail: string | null;
};

export type IntegrationSyncResult = {
  alerts_staged: number;
  absence_candidates?: number;
  missing_source_records?: number;
};

type Toast = (options: {
  title: string;
  description?: string;
  tone: "ok" | "danger";
}) => void;

export function configuredTenableScanIds(config: Record<string, unknown>): string[] {
  const value = config.scan_ids;
  if (!Array.isArray(value)) return [];
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return value.filter((scan): scan is string => typeof scan === "string" && uuid.test(scan));
}

export function handleIntegrationTestSuccess(
  result: IntegrationTestResult,
  { refresh, toast }: { refresh: () => void; toast: Toast },
) {
  refresh();
  toast({
    title: result.healthy ? "Healthy" : "Unhealthy",
    description: result.detail || undefined,
    tone: result.healthy ? "ok" : "danger",
  });
}

export function handleIntegrationSyncSuccess(
  result: IntegrationSyncResult,
  { toast }: { toast: Toast },
) {
  const messages = [
    `${result.alerts_staged} alerts are available in Findings → External alerts.`,
  ];
  if (result.absence_candidates) {
    messages.push(
      `${result.absence_candidates} missing source records evaluated against the closure policy.`,
    );
  }
  if (result.missing_source_records) {
    messages.push(
      `${result.missing_source_records} source records were not returned and are marked stale; their findings remain open.`,
    );
  }
  toast({
    title: "Security alerts synchronized",
    description: messages.join(" "),
    tone: "ok",
  });
}
