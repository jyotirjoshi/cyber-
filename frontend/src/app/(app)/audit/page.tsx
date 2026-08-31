"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { formatDateTime, humanize } from "@/lib/format";
import type { AuditFilter, AuditOutcome } from "@/lib/types";

const PAGE_SIZE = 50;

const OUTCOMES: readonly AuditOutcome[] = ["success", "failure", "denied"];

type ActorTypeChoice = NonNullable<AuditFilter["actor_type"]>;
const ACTOR_TYPES: readonly ActorTypeChoice[] = ["user", "agent", "worker", "system"];

/** Outcome → semantic Badge tone (static; never interpolated into a class name). */
const OUTCOME_TONE: Record<AuditOutcome, "ok" | "danger" | "warn"> = {
  success: "ok",
  failure: "danger",
  denied: "warn",
};

export default function AuditPage() {
  const { can } = useAuth();

  const [q, setQ] = React.useState("");
  const [outcome, setOutcome] = React.useState<AuditOutcome | "">("");
  const [actorType, setActorType] = React.useState<ActorTypeChoice | "">("");
  const [action, setAction] = React.useState("");
  const [resourceType, setResourceType] = React.useState("");
  const [offset, setOffset] = React.useState(0);
  const [open, setOpen] = React.useState<Set<string>>(new Set());

  const debouncedQ = useDebouncedValue(q);
  const debouncedAction = useDebouncedValue(action);
  const debouncedResourceType = useDebouncedValue(resourceType);
  const canRead = can("audit:read");

  const { data, error, loading, refetch } = useApiResource(
    () =>
      api.audit.list({
        limit: PAGE_SIZE,
        offset,
        q: debouncedQ.trim() || undefined,
        outcome: outcome || undefined,
        actor_type: actorType || undefined,
        action: debouncedAction.trim() || undefined,
        resource_type: debouncedResourceType.trim() || undefined,
      }),
    [debouncedQ, outcome, actorType, debouncedAction, debouncedResourceType, offset],
    { enabled: canRead },
  );

  const toggle = React.useCallback((id: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  if (!canRead) {
    return (
      <div className="space-y-6">
        <PageHeader title="Audit log" />
        <EmptyState title="No access" description="You don't have permission to view this." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        description="Security-relevant actions across your organization, with full request context."
      />

      <Card>
        <CardBody className="space-y-4">
          <Field label="Search" htmlFor="a-q">
            <Input
              id="a-q"
              type="search"
              placeholder="Search actor, action, resource…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setOffset(0);
              }}
            />
          </Field>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Outcome" htmlFor="a-outcome">
              <Select
                id="a-outcome"
                value={outcome}
                onChange={(e) => {
                  setOutcome(e.target.value as AuditOutcome | "");
                  setOffset(0);
                }}
              >
                <option value="">All outcomes</option>
                {OUTCOMES.map((o) => (
                  <option key={o} value={o}>
                    {humanize(o)}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Actor type" htmlFor="a-actor-type">
              <Select
                id="a-actor-type"
                value={actorType}
                onChange={(e) => {
                  setActorType(e.target.value as ActorTypeChoice | "");
                  setOffset(0);
                }}
              >
                <option value="">All actor types</option>
                {ACTOR_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {humanize(t)}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Action" htmlFor="a-action">
              <Input
                id="a-action"
                type="text"
                placeholder="e.g. assessment.create"
                value={action}
                onChange={(e) => {
                  setAction(e.target.value);
                  setOffset(0);
                }}
              />
            </Field>

            <Field label="Resource type" htmlFor="a-resource-type">
              <Input
                id="a-resource-type"
                type="text"
                placeholder="e.g. assessment"
                value={resourceType}
                onChange={(e) => {
                  setResourceType(e.target.value);
                  setOffset(0);
                }}
              />
            </Field>
          </div>
        </CardBody>
      </Card>

      {loading && !data ? (
        <LoadingState label="Loading audit events…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="No audit events" description="No audit events match your current filters." />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH className="w-10">
                  <span className="sr-only">Expand</span>
                </TH>
                <TH>Time</TH>
                <TH>Actor</TH>
                <TH>Action</TH>
                <TH>Resource</TH>
                <TH>Outcome</TH>
                <TH>Request</TH>
              </TR>
            </THead>
            <TBody>
              {data.items.map((e) => {
                const isOpen = open.has(e.id);
                return (
                  <React.Fragment key={e.id}>
                    <TR clickable aria-expanded={isOpen} onClick={() => toggle(e.id)}>
                      <TD className="w-10 pr-0 text-faint">
                        <svg
                          viewBox="0 0 16 16"
                          className={cn(
                            "h-3.5 w-3.5 transition-transform",
                            isOpen && "rotate-90",
                          )}
                          fill="none"
                          aria-hidden="true"
                        >
                          <path
                            d="M6 4l4 4-4 4"
                            stroke="currentColor"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        </svg>
                      </TD>
                      <TD className="whitespace-nowrap text-muted">
                        {formatDateTime(e.created_at)}
                      </TD>
                      <TD>
                        <span className="block max-w-[16rem] truncate text-fg" title={e.actor_email ?? undefined}>
                          {e.actor_email ?? humanize(e.actor_type)}
                        </span>
                      </TD>
                      <TD>
                        <span className="font-mono text-xs text-fg">{e.action}</span>
                      </TD>
                      <TD className="text-muted">
                        {e.resource_type ? (
                          <span
                            className="block max-w-[18rem] truncate font-mono text-xs"
                            title={`${e.resource_type}/${e.resource_id ?? ""}`}
                          >
                            {`${e.resource_type}/${e.resource_id ?? ""}`}
                          </span>
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </TD>
                      <TD>
                        <Badge tone={OUTCOME_TONE[e.outcome]}>{humanize(e.outcome)}</Badge>
                      </TD>
                      <TD>
                        <span
                          className="block max-w-[10rem] truncate font-mono text-xs text-muted"
                          title={e.request_id ?? undefined}
                        >
                          {e.request_id ?? "—"}
                        </span>
                      </TD>
                    </TR>
                    {isOpen && (
                      <TR>
                        <TD colSpan={7} className="bg-surface-2/40">
                          <div className="space-y-3 py-1">
                            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-3">
                              <div>
                                <dt className="text-xs font-medium uppercase tracking-wide text-faint">
                                  Reason
                                </dt>
                                <dd className="mt-0.5 text-sm text-fg">{e.reason ?? "—"}</dd>
                              </div>
                              <div>
                                <dt className="text-xs font-medium uppercase tracking-wide text-faint">
                                  Source IP
                                </dt>
                                <dd className="mt-0.5 font-mono text-sm text-fg">
                                  {e.source_ip ?? "—"}
                                </dd>
                              </div>
                              <div>
                                <dt className="text-xs font-medium uppercase tracking-wide text-faint">
                                  User agent
                                </dt>
                                <dd className="mt-0.5 break-all text-sm text-fg">
                                  {e.user_agent ?? "—"}
                                </dd>
                              </div>
                            </dl>
                            <div>
                              <p className="mb-1 text-xs font-medium uppercase tracking-wide text-faint">
                                Detail
                              </p>
                              <pre className="overflow-x-auto rounded-lg border border-line bg-bg p-3 text-xs text-muted">
                                {JSON.stringify(e.detail, null, 2)}
                              </pre>
                            </div>
                          </div>
                        </TD>
                      </TR>
                    )}
                  </React.Fragment>
                );
              })}
            </TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </div>
      )}
    </div>
  );
}
