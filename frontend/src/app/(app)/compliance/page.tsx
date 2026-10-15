"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { humanize } from "@/lib/format";
import type { ComplianceControlStatus, ComplianceFramework } from "@/lib/types";

const FRAMEWORKS: Array<{ id: ComplianceFramework; label: string }> = [
  { id: "pci_dss", label: "PCI DSS" },
  { id: "iso_27001", label: "ISO 27001" },
  { id: "soc_2", label: "SOC 2" },
  { id: "hipaa", label: "HIPAA" },
  { id: "nist_csf", label: "NIST CSF" },
  { id: "cis_controls", label: "CIS Controls" },
];

function statusTone(status: ComplianceControlStatus): "ok" | "warn" | "danger" | "neutral" {
  if (status === "satisfied") return "ok";
  if (status === "at_risk") return "danger";
  if (status === "partially_satisfied") return "warn";
  return "neutral";
}

export default function CompliancePage() {
  const { can } = useAuth();
  const canRead = can("finding:read");
  const canManage = can("org:manage");
  const [selectedFramework, setSelectedFramework] = React.useState<ComplianceFramework | "">("");
  const [busyFramework, setBusyFramework] = React.useState<ComplianceFramework | null>(null);
  const [mutationError, setMutationError] = React.useState<string | null>(null);

  const overview = useApiResource(() => api.compliance.overview(), [], { enabled: canRead });
  const controls = useApiResource(
    () => api.compliance.controls(selectedFramework || undefined),
    [selectedFramework],
    { enabled: canRead },
  );

  const seed = async (framework: ComplianceFramework) => {
    if (!canManage || busyFramework) return;
    setBusyFramework(framework);
    setMutationError(null);
    try {
      await api.compliance.seed(framework);
      overview.refetch();
      controls.refetch();
    } catch (error) {
      setMutationError(getErrorMessage(error));
    } finally {
      setBusyFramework(null);
    }
  };

  if (!canRead) {
    return <EmptyState title="No access" description="You don't have permission to view compliance evidence." />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance"
        description="Evidence-backed control coverage from canonical findings. This supports audit readiness; it is not a certification decision."
      />

      {overview.loading && !overview.data ? <LoadingState label="Loading compliance coverage…" /> : overview.error ? <ErrorState message={overview.error} onRetry={overview.refetch} /> : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {overview.data?.frameworks.map((framework) => (
            <Card key={framework.framework}>
              <CardBody className="space-y-2">
                <div className="flex items-center justify-between gap-3"><h2 className="text-sm font-semibold text-fg">{FRAMEWORKS.find((item) => item.id === framework.framework)?.label ?? humanize(framework.framework)}</h2><Badge tone={framework.at_risk_control_count ? "danger" : "neutral"}>{framework.coverage_percent.toFixed(0)}% mapped</Badge></div>
                <p className="text-xs text-muted">{framework.control_count} controls · {framework.mapped_control_count} mapped · {framework.active_finding_count} active finding links</p>
                <div className="text-sm text-fg"><span className="font-semibold text-danger">{framework.at_risk_control_count}</span> at risk · <span className="font-semibold text-warn">{framework.partially_satisfied_control_count}</span> partial · <span className="font-semibold text-ok">{framework.satisfied_control_count}</span> satisfied</div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <Card>
        <CardBody className="space-y-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><h2 className="text-sm font-semibold text-fg">Controls</h2><p className="text-xs text-muted">A control becomes at risk when an unresolved mapped finding has a risk score of 70 or higher.</p></div><select aria-label="Compliance framework" className="h-9 rounded-lg border border-line bg-surface-2 px-2 text-sm text-fg" value={selectedFramework} onChange={(event) => setSelectedFramework(event.target.value as ComplianceFramework | "")}><option value="">All frameworks</option>{FRAMEWORKS.map((framework) => <option key={framework.id} value={framework.id}>{framework.label}</option>)}</select></div>
          {canManage && <div className="flex flex-wrap gap-2 border-t border-line pt-3">{FRAMEWORKS.map((framework) => <Button key={framework.id} size="sm" variant="outline" loading={busyFramework === framework.id} disabled={busyFramework !== null} onClick={() => void seed(framework.id)}>Activate {framework.label}</Button>)}</div>}
          {mutationError && <p role="alert" className="text-sm text-danger">{mutationError}</p>}
          {controls.loading && !controls.data ? <LoadingState label="Loading controls…" /> : controls.error ? <ErrorState message={controls.error} onRetry={controls.refetch} /> : !controls.data?.length ? <EmptyState title="No controls activated" description={canManage ? "Activate a starter framework above, then map its controls to canonical findings." : "Ask an organization manager to activate a framework."} /> : (
            <Table><THead><TR><TH>Framework</TH><TH>Control</TH><TH>Status</TH><TH>Finding links</TH><TH>Highest risk</TH></TR></THead><TBody>{controls.data.map((control) => <TR key={control.id}><TD>{FRAMEWORKS.find((item) => item.id === control.framework)?.label ?? humanize(control.framework)}</TD><TD><div className="font-medium text-fg">{control.control_id}</div><div className="text-xs text-muted">{control.title}</div></TD><TD><Badge tone={statusTone(control.effective_status)}>{humanize(control.effective_status)}</Badge></TD><TD>{control.active_finding_count} active / {control.mapped_finding_count} mapped</TD><TD>{control.highest_risk_score === null ? "—" : `${control.highest_risk_score.toFixed(0)}/100`}</TD></TR>)}</TBody></Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
