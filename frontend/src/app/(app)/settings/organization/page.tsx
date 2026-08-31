"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fieldError } from "@/lib/errors";
import { formatDateTime, formatNumber, humanize } from "@/lib/format";
import type {
  MemberInviteIn,
  MemberOut,
  OrganizationOut,
  OrganizationUpdateIn,
  Role,
} from "@/lib/types";

const ROLES: readonly Role[] = [
  "owner",
  "admin",
  "security_engineer",
  "developer",
  "viewer",
];

// --- Organization profile ---------------------------------------------------

function OrgSummary({ org }: { org: OrganizationOut }) {
  return (
    <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div>
        <dt className="text-xs font-medium text-muted">Name</dt>
        <dd className="mt-1 text-sm text-fg">{org.name}</dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Slug</dt>
        <dd className="mt-1 font-mono text-sm text-fg">{org.slug}</dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Status</dt>
        <dd className="mt-1">
          <Badge tone={org.is_active ? "ok" : "neutral"}>
            {org.is_active ? "Active" : "Inactive"}
          </Badge>
        </dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Max concurrent scanner jobs</dt>
        <dd className="mt-1 text-sm text-fg">
          {formatNumber(org.max_concurrent_scanner_jobs)}
        </dd>
      </div>
    </dl>
  );
}

function OrgEditForm({
  org,
  onUpdated,
}: {
  org: OrganizationOut;
  onUpdated: (next: OrganizationOut) => void;
}) {
  const { toast } = useToast();
  const [name, setName] = React.useState(org.name);
  const [maxJobs, setMaxJobs] = React.useState(String(org.max_concurrent_scanner_jobs));
  const [policyText, setPolicyText] = React.useState("");
  const [policyError, setPolicyError] = React.useState<string | null>(null);

  const mutation = useMutation(
    (body: OrganizationUpdateIn) => api.organization.update(body),
    {
      onSuccess: (next) => {
        onUpdated(next);
        toast({ title: "Organization updated", tone: "ok" });
      },
    },
  );

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setPolicyError(null);

    const body: OrganizationUpdateIn = { name: name.trim() };

    const maxNum = maxJobs.trim() === "" ? Number.NaN : Number(maxJobs);
    if (!Number.isNaN(maxNum)) body.max_concurrent_scanner_jobs = maxNum;

    const trimmedPolicy = policyText.trim();
    if (trimmedPolicy) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmedPolicy);
      } catch {
        setPolicyError("Enter valid JSON, or leave blank.");
        return;
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setPolicyError("Policy must be a JSON object.");
        return;
      }
      body.policy = parsed as Record<string, unknown>;
    }

    void mutation.run(body);
  };

  const generalError =
    fieldError(mutation.error, "name") ||
    fieldError(mutation.error, "max_concurrent_scanner_jobs")
      ? null
      : mutation.errorMessage;

  return (
    <form onSubmit={onSubmit} className="space-y-4 border-t border-line pt-6">
      <h3 className="text-sm font-semibold text-fg">Edit profile</h3>
      <InlineError message={generalError} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field
          label="Name"
          htmlFor="org-name"
          required
          error={fieldError(mutation.error, "name")}
        >
          <Input
            id="org-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </Field>
        <Field
          label="Max concurrent scanner jobs"
          htmlFor="org-max-jobs"
          hint="Between 1 and 64."
          error={fieldError(mutation.error, "max_concurrent_scanner_jobs")}
        >
          <Input
            id="org-max-jobs"
            type="number"
            min={1}
            max={64}
            value={maxJobs}
            onChange={(e) => setMaxJobs(e.target.value)}
          />
        </Field>
      </div>
      <Field
        label="Policy (JSON)"
        htmlFor="org-policy"
        hint="Optional. Leave blank to keep the current policy."
        error={policyError}
      >
        <Textarea
          id="org-policy"
          rows={5}
          value={policyText}
          onChange={(e) => setPolicyText(e.target.value)}
          className="font-mono text-xs"
          placeholder={'{ "key": "value" }'}
        />
      </Field>
      <div className="flex justify-end">
        <Button type="submit" loading={mutation.loading}>
          Save changes
        </Button>
      </div>
    </form>
  );
}

// --- Members ----------------------------------------------------------------

function InviteForm({ onInvited }: { onInvited: () => void }) {
  const { toast } = useToast();
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<Role>("viewer");
  const [fullName, setFullName] = React.useState("");

  const mutation = useMutation(
    (body: MemberInviteIn) => api.organization.inviteMember(body),
    {
      onSuccess: (member) => {
        onInvited();
        toast({ title: "Invitation sent", description: member.email, tone: "ok" });
        setEmail("");
        setFullName("");
        setRole("viewer");
      },
    },
  );

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    void mutation.run({
      email: email.trim(),
      role,
      full_name: fullName.trim() || null,
    });
  };

  const generalError =
    fieldError(mutation.error, "email") ||
    fieldError(mutation.error, "full_name") ||
    fieldError(mutation.error, "role")
      ? null
      : mutation.errorMessage;

  return (
    <form
      onSubmit={onSubmit}
      className="space-y-4 rounded-lg border border-line bg-surface-2/40 p-4"
    >
      <h3 className="text-sm font-semibold text-fg">Invite a member</h3>
      <InlineError message={generalError} />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Field
          label="Email"
          htmlFor="invite-email"
          required
          error={fieldError(mutation.error, "email")}
          className="lg:col-span-2"
        >
          <Input
            id="invite-email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="person@example.com"
          />
        </Field>
        <Field
          label="Full name"
          htmlFor="invite-name"
          error={fieldError(mutation.error, "full_name")}
        >
          <Input
            id="invite-name"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            placeholder="Optional"
          />
        </Field>
        <Field
          label="Role"
          htmlFor="invite-role"
          error={fieldError(mutation.error, "role")}
        >
          <Select
            id="invite-role"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {humanize(r)}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <div className="flex justify-end">
        <Button type="submit" loading={mutation.loading}>
          Send invitation
        </Button>
      </div>
    </form>
  );
}

function MemberRow({
  member,
  canManage,
  onChanged,
}: {
  member: MemberOut;
  canManage: boolean;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [pendingRole, setPendingRole] = React.useState<Role | null>(null);

  const roleMutation = useMutation(
    (role: Role) => api.organization.updateMemberRole(member.membership_id, { role }),
    {
      onSuccess: () => {
        setPendingRole(null);
        onChanged();
        toast({ title: "Role updated", description: member.email, tone: "ok" });
      },
      onError: () => {
        setPendingRole(null);
        toast({ title: "Couldn't update role", description: member.email, tone: "danger" });
      },
    },
  );

  const removeMutation = useMutation(
    () => api.organization.removeMember(member.membership_id),
    {
      onSuccess: () => {
        onChanged();
        toast({ title: "Member removed", description: member.email, tone: "ok" });
      },
      onError: () => {
        toast({ title: "Couldn't remove member", description: member.email, tone: "danger" });
      },
    },
  );

  const onRemove = () => {
    if (!window.confirm(`Remove ${member.email} from the organization?`)) return;
    void removeMutation.run();
  };

  return (
    <TR>
      <TD>{member.email}</TD>
      <TD>{member.full_name || "—"}</TD>
      <TD>
        {canManage ? (
          <Select
            value={pendingRole ?? member.role}
            disabled={roleMutation.loading}
            aria-label={`Role for ${member.email}`}
            className="h-8 py-1 text-xs"
            onChange={(e) => {
              const next = e.target.value as Role;
              setPendingRole(next);
              void roleMutation.run(next);
            }}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {humanize(r)}
              </option>
            ))}
          </Select>
        ) : (
          humanize(member.role)
        )}
      </TD>
      <TD>
        <Badge tone={member.is_active ? "ok" : "neutral"}>
          {member.is_active ? "Active" : "Inactive"}
        </Badge>
      </TD>
      <TD className="text-muted">{formatDateTime(member.last_login_at)}</TD>
      {canManage && (
        <TD className="text-right">
          <Button
            variant="danger"
            size="sm"
            loading={removeMutation.loading}
            onClick={onRemove}
          >
            Remove
          </Button>
        </TD>
      )}
    </TR>
  );
}

// --- Page -------------------------------------------------------------------

export default function OrganizationPage() {
  const { can } = useAuth();
  const canRead = can("org:read");
  const canManageOrg = can("org:manage");
  const canManageMembers = can("member:manage");

  const org = useApiResource(() => api.organization.get(), [canRead], {
    enabled: canRead,
  });
  const members = useApiResource(
    () => api.organization.members({ limit: 100, offset: 0 }),
    [canRead],
    { enabled: canRead },
  );

  if (!canRead) {
    return (
      <div className="space-y-6">
        <PageHeader title="Organization" />
        <EmptyState
          title="No access"
          description="You don't have permission to view this."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organization"
        description="Manage your organization profile and team members."
      />

      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
        <CardBody className="space-y-6">
          {org.loading && !org.data ? (
            <LoadingState />
          ) : org.error ? (
            <ErrorState message={org.error} onRetry={org.refetch} />
          ) : org.data ? (
            <>
              <OrgSummary org={org.data} />
              {canManageOrg && <OrgEditForm org={org.data} onUpdated={org.setData} />}
            </>
          ) : null}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
        </CardHeader>
        <CardBody className="space-y-6">
          {canManageMembers && <InviteForm onInvited={members.refetch} />}

          {members.loading && !members.data ? (
            <LoadingState />
          ) : members.error ? (
            <ErrorState message={members.error} onRetry={members.refetch} />
          ) : !members.data || members.data.items.length === 0 ? (
            <EmptyState
              title="No members"
              description="No members found for this organization."
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Email</TH>
                  <TH>Name</TH>
                  <TH>Role</TH>
                  <TH>Active</TH>
                  <TH>Last login</TH>
                  {canManageMembers && <TH className="text-right">Actions</TH>}
                </TR>
              </THead>
              <TBody>
                {members.data.items.map((m) => (
                  <MemberRow
                    key={m.membership_id}
                    member={m}
                    canManage={canManageMembers}
                    onChanged={members.refetch}
                  />
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
