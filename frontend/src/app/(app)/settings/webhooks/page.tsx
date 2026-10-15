"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/format";
import type {
  WebhookDeliveryOut,
  WebhookSubscriptionIssuedOut,
  WebhookSubscriptionOut,
} from "@/lib/types";

const ALL_EVENTS = [
  "assessment.completed",
  "assessment.failed",
  "finding.created",
  "asset.created",
  "sla.breached",
  "ticket.created",
  "ticket.closed",
];

export default function WebhooksPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("org:manage");

  const [showCreate, setShowCreate] = React.useState(false);
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [selectedEvents, setSelectedEvents] = React.useState<Set<string>>(new Set(ALL_EVENTS));
  const [issued, setIssued] = React.useState<WebhookSubscriptionIssuedOut | null>(null);
  const [deliveryTarget, setDeliveryTarget] = React.useState<string | null>(null);
  const [deliveryTargetId, setDeliveryTargetId] = React.useState<string | null>(null);
  const [deliveries, setDeliveries] = React.useState<WebhookDeliveryOut[]>([]);

  const { data, error, loading, refetch } = useApiResource(
    () => api.platform.listWebhooks(),
    [],
  );

  const createMut = useMutation(
    () => api.platform.createWebhook({ name, url, event_types: [...selectedEvents] }),
    {
      onSuccess: (subscription) => {
        setIssued(subscription);
        toast({ title: "Webhook created", tone: "ok" });
        setShowCreate(false);
        setName("");
        setUrl("");
        setSelectedEvents(new Set(ALL_EVENTS));
        void refetch();
      },
    },
  );

  const disableMut = useMutation(
    (id: string) => api.platform.disableWebhook(id),
    {
      onSuccess: () => {
        toast({ title: "Webhook disabled", tone: "ok" });
        void refetch();
      },
    },
  );

  const rotateMut = useMutation(
    (id: string) => api.platform.rotateWebhookSecret(id),
    {
      onSuccess: (subscription) => {
        setIssued(subscription);
        toast({ title: "Webhook secret rotated", tone: "ok" });
        void refetch();
      },
    },
  );

  const deliveriesMut = useMutation(
    (id: string) => api.platform.listWebhookDeliveries(id),
    {
      onSuccess: (items) => setDeliveries(items),
    },
  );

  function openDeliveries(webhook: WebhookSubscriptionOut) {
    setDeliveryTarget(webhook.name);
    setDeliveryTargetId(webhook.id);
    setDeliveries([]);
    void deliveriesMut.run(webhook.id);
  }

  const retryDeliveryMut = useMutation(
    ({ subscriptionId, deliveryId }: { subscriptionId: string; deliveryId: string }) =>
      api.platform.retryWebhookDelivery(subscriptionId, deliveryId),
    {
      onSuccess: (delivery) => {
        setDeliveries((items) => items.map((item) => (item.id === delivery.id ? delivery : item)));
        toast({ title: "Webhook delivery requeued", tone: "ok" });
      },
    },
  );

  function toggleEvent(ev: string) {
    setSelectedEvents((prev) => {
      const next = new Set(prev);
      if (next.has(ev)) next.delete(ev);
      else next.add(ev);
      return next;
    });
  }

  const rows: WebhookSubscriptionOut[] = data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhooks"
        description="HMAC-signed outbound event notifications to your own endpoints."
        action={canManage && <Button onClick={() => setShowCreate(true)}>Add webhook</Button>}
      />

      {loading && !rows.length ? (
        <LoadingState label="Loading webhooks…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !rows.length ? (
        <EmptyState
          title="No webhooks"
          description="Add a webhook to receive signed event notifications in your own systems."
          action={canManage ? <Button onClick={() => setShowCreate(true)}>Add webhook</Button> : undefined}
        />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Name</TH>
              <TH>URL</TH>
              <TH>Events</TH>
              <TH>Status</TH>
              {canManage && <TH className="w-64" />}
            </TR>
          </THead>
          <TBody>
            {rows.map((w) => (
              <TR key={w.id}>
                <TD className="font-medium text-fg">{w.name}</TD>
                <TD>
                  <span className="block max-w-[22rem] truncate font-mono text-xs text-muted" title={w.url}>
                    {w.url}
                  </span>
                </TD>
                <TD className="text-muted text-xs">{w.event_types.length} event{w.event_types.length !== 1 ? "s" : ""}</TD>
                <TD>
                  <Badge tone={w.is_enabled ? "ok" : "neutral"}>{w.is_enabled ? "Active" : "Disabled"}</Badge>
                </TD>
                {canManage && (
                  <TD>
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        className="text-xs text-muted hover:underline"
                        onClick={() => openDeliveries(w)}
                      >
                        Deliveries
                      </button>
                      <button
                        type="button"
                        className="text-xs text-accent hover:underline"
                        disabled={!w.is_enabled || rotateMut.loading}
                        onClick={() => void rotateMut.run(w.id)}
                      >
                        Rotate secret
                      </button>
                      <button
                        type="button"
                        className="text-xs text-danger hover:underline"
                        disabled={!w.is_enabled || disableMut.loading}
                        onClick={() => void disableMut.run(w.id)}
                      >
                        {w.is_enabled ? "Disable" : "Disabled"}
                      </button>
                    </div>
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {issued && (
        <Modal title="Webhook signing secret" onClose={() => setIssued(null)}>
          <div className="space-y-4">
            <p className="text-sm text-muted">
              Copy this secret now. It is shown only once and replaces any previous secret.
            </p>
            <code className="block break-all rounded border border-border bg-surface-2 p-3 text-xs text-fg">
              {issued.secret}
            </code>
            <div className="flex justify-end">
              <Button onClick={() => setIssued(null)}>I have saved it</Button>
            </div>
          </div>
        </Modal>
      )}

      {deliveryTarget && (
        <Modal title={`Recent deliveries — ${deliveryTarget}`} onClose={() => {
          setDeliveryTarget(null);
          setDeliveryTargetId(null);
        }}>
          <div className="space-y-3">
            {deliveriesMut.loading ? (
              <LoadingState label="Loading delivery history…" />
            ) : deliveriesMut.errorMessage ? (
              <p role="alert" className="text-sm text-danger">{deliveriesMut.errorMessage}</p>
            ) : !deliveries.length ? (
              <p className="text-sm text-muted">No delivery attempts have been recorded yet.</p>
            ) : (
              <div className="max-h-96 space-y-2 overflow-y-auto">
                {deliveries.map((delivery) => (
                  <div key={delivery.id} className="rounded border border-border p-3 text-sm">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-medium text-fg">{delivery.event}</span>
                      <Badge tone={delivery.status === "sent" ? "ok" : delivery.status === "failed" ? "danger" : "neutral"}>
                        {delivery.status}
                      </Badge>
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      {formatDateTime(delivery.sent_at ?? delivery.created_at)} · {delivery.attempts} attempt{delivery.attempts === 1 ? "" : "s"}
                    </p>
                    {delivery.status === "pending" && delivery.next_retry_at && (
                      <p className="mt-1 text-xs text-warn">
                        Automatic retry scheduled for {formatDateTime(delivery.next_retry_at)}
                      </p>
                    )}
                    {delivery.last_error && <p className="mt-2 text-xs text-danger">{delivery.last_error}</p>}
                    {delivery.status === "failed" && deliveryTargetId && canManage && (
                      <button
                        type="button"
                        className="mt-2 text-xs text-accent hover:underline"
                        disabled={retryDeliveryMut.loading}
                        onClick={() => void retryDeliveryMut.run({
                          subscriptionId: deliveryTargetId,
                          deliveryId: delivery.id,
                        })}
                      >
                        Retry delivery
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </Modal>
      )}

      {showCreate && (
        <Modal title="Add webhook" onClose={() => setShowCreate(false)}>
          <form onSubmit={(e) => { e.preventDefault(); void createMut.run(); }} className="space-y-4">
            <Field label="Name" htmlFor="wh-name">
              <Input id="wh-name" required maxLength={160} value={name}
                onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="URL (HTTPS)" htmlFor="wh-url">
              <Input id="wh-url" required type="url" value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://hooks.example.com/cynux" />
            </Field>
            <fieldset>
              <legend className="mb-2 text-sm font-medium text-fg">Events</legend>
              <div className="grid grid-cols-2 gap-2">
                {ALL_EVENTS.map((ev) => (
                  <label key={ev} className="flex items-center gap-2 text-sm text-muted">
                    <input
                      type="checkbox"
                      checked={selectedEvents.has(ev)}
                      onChange={() => toggleEvent(ev)}
                    />
                    {ev}
                  </label>
                ))}
              </div>
            </fieldset>
            {createMut.errorMessage && <p role="alert" className="text-sm text-danger">{createMut.errorMessage}</p>}
            <div className="flex justify-end gap-3">
              <Button type="button" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" loading={createMut.loading}>Create webhook</Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
