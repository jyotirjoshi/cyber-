"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, humanize } from "@/lib/format";
import type { ExternalDeliveryOut } from "@/lib/types";

const STATUS_OPTIONS = ["", "pending", "failed", "sent"] as const;

function tone(status: ExternalDeliveryOut["status"]) {
  return status === "sent" ? "ok" : status === "failed" ? "danger" : "warn";
}

export default function DeliveryOperationsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const [status, setStatus] = React.useState<(typeof STATUS_OPTIONS)[number]>("");
  const canManage = can("org:manage");
  const deliveries = useApiResource(
    () => api.notifications.listDeliveries(status || undefined),
    [status],
    { enabled: canManage },
  );
  const retry = useMutation(
    (id: string) => api.notifications.retryDelivery(id),
    {
      onSuccess: () => {
        toast({ title: "Delivery requeued", tone: "ok" });
        void deliveries.refetch();
      },
    },
  );

  if (!canManage) {
    return <EmptyState title="No access" description="Organization administrators can manage outbound delivery operations." />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Delivery operations"
        description="Durable Slack, email, PagerDuty, Splunk HEC, and webhook delivery history. Fix an integration, then requeue terminal failures."
        actions={<Button variant="secondary" onClick={() => void deliveries.refetch()}>Refresh</Button>}
      />
      <div className="flex flex-wrap items-center gap-2">
        {STATUS_OPTIONS.map((option) => (
          <Button
            key={option || "all"}
            size="sm"
            variant={status === option ? "primary" : "secondary"}
            onClick={() => setStatus(option)}
          >
            {option ? humanize(option) : "All"}
          </Button>
        ))}
      </div>
      {deliveries.loading && !deliveries.data ? <LoadingState label="Loading delivery history…" /> : deliveries.error ? <ErrorState message={deliveries.error} onRetry={deliveries.refetch} /> : !deliveries.data?.length ? <EmptyState title="No deliveries" description="External notification deliveries will appear here once Cynux sends them." /> : (
        <Table>
          <THead><TR><TH>When</TH><TH>Channel</TH><TH>Event</TH><TH>Recipient</TH><TH>Status</TH><TH>Attempts</TH><TH>Action</TH></TR></THead>
          <TBody>{deliveries.data.map((delivery) => (
            <TR key={delivery.id}>
              <TD className="text-xs text-muted">{formatDateTime(delivery.sent_at ?? delivery.created_at)}</TD>
              <TD>{humanize(delivery.channel)}</TD>
              <TD className="text-xs">{humanize(delivery.event)}</TD>
              <TD className="max-w-48 truncate text-xs text-muted" title={delivery.recipient}>{delivery.recipient}</TD>
              <TD><Badge tone={tone(delivery.status)}>{humanize(delivery.status)}</Badge>{delivery.last_error && <p className="mt-1 max-w-52 text-xs text-danger">{delivery.last_error}</p>}{delivery.next_retry_at && <p className="mt-1 text-xs text-muted">Retry {formatDateTime(delivery.next_retry_at)}</p>}</TD>
              <TD>{delivery.attempts}</TD>
              <TD>{delivery.status === "failed" ? <Button size="sm" variant="secondary" loading={retry.loading} onClick={() => void retry.run(delivery.id)}>Retry</Button> : "—"}</TD>
            </TR>
          ))}</TBody>
        </Table>
      )}
    </div>
  );
}
