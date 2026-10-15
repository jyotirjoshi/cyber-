"use client";

import Link from "next/link";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";

export default function ReportPortfolioPage() {
  const portfolio = useApiResource(() => api.reports.portfolio(), []);
  const totals = (portfolio.data ?? []).reduce((sum, row) => ({ clients: sum.clients + 1, assets: sum.assets + row.asset_count, findings: sum.findings + row.open_finding_count, critical: sum.critical + row.critical_open_finding_count, risk: sum.risk + row.open_risk_score }), { clients: 0, assets: 0, findings: 0, critical: 0, risk: 0 });
  return <div className="space-y-6"><PageHeader title="MSSP portfolio reporting" description="Aggregate posture for directly managed customer organizations. Raw customer findings remain tenant-isolated." action={<Link href="/reports"><Button variant="ghost">Reports</Button></Link>} />
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">{[["Clients", totals.clients], ["Assets", totals.assets], ["Open findings", totals.findings], ["Critical", totals.critical], ["Open risk", totals.risk.toFixed(1)]].map(([label, value]) => <Card key={label}><CardBody><p className="text-xs uppercase text-muted">{label}</p><p className="mt-1 text-2xl font-semibold text-fg">{value}</p></CardBody></Card>)}</div>
    {portfolio.loading && !portfolio.data ? <LoadingState label="Loading portfolio…" /> : portfolio.error ? <ErrorState message={portfolio.error} onRetry={portfolio.refetch} /> : !portfolio.data?.length ? <EmptyState title="No managed clients" description="Create client organizations before generating portfolio views." /> : <Table><THead><TR><TH>Client</TH><TH>Assets</TH><TH>Open findings</TH><TH>Critical</TH><TH>Open risk</TH></TR></THead><TBody>{portfolio.data.map((row) => <TR key={row.organization.id}><TD className="font-medium text-fg">{row.organization.name}</TD><TD>{row.asset_count}</TD><TD>{row.open_finding_count}</TD><TD>{row.critical_open_finding_count}</TD><TD>{row.open_risk_score.toFixed(1)}</TD></TR>)}</TBody></Table>}
  </div>;
}
