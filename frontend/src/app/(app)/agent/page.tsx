"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { countLabel, formatRelative } from "@/lib/format";
import { MAX_MESSAGE_LENGTH } from "@/lib/types";

/**
 * Agent index — the natural-language entry point. Starts a new conversation (a message with no
 * `session_id` mints one server-side, FR-002/FR-003) and lists prior sessions to resume. The live
 * plan / approval / streaming experience lives in `/agent/[sessionId]`.
 */
export default function AgentIndexPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { can } = useAuth();
  const canChat = can("agent:chat");

  const sessions = useApiResource(
    () => api.agent.sessions({ limit: 50 }),
    [],
    { enabled: canChat },
  );

  const [content, setContent] = React.useState("");
  const [starting, setStarting] = React.useState(false);

  const start = async () => {
    const trimmed = content.trim();
    if (!trimmed || starting) return;
    setStarting(true);
    try {
      const message = await api.agent.sendMessage({ content: trimmed });
      router.push(`/agent/${message.session_id}`);
    } catch (error) {
      toast({
        title: "Could not start the conversation",
        description: getErrorMessage(error),
        tone: "danger",
      });
      setStarting(false);
    }
  };

  if (!canChat) {
    return (
      <EmptyState
        title="No access"
        description="You don't have permission to use the security agent."
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security agent"
        description="Describe an objective in plain language. The agent plans, runs passive recon, and pauses for your approval before any active scan."
      />

      <Card>
        <CardBody className="space-y-3">
          <Textarea
            aria-label="Describe your objective"
            placeholder="e.g. Assess the external attack surface of example.com and prioritise anything internet-exposed."
            rows={4}
            maxLength={MAX_MESSAGE_LENGTH}
            value={content}
            onChange={(event) => setContent(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                event.preventDefault();
                void start();
              }
            }}
          />
          <div className="flex items-center justify-between">
            <span className="text-xs text-faint">
              {content.length}/{MAX_MESSAGE_LENGTH} · ⌘/Ctrl + Enter to send
            </span>
            <Button loading={starting} disabled={!content.trim()} onClick={() => void start()}>
              Start conversation
            </Button>
          </div>
        </CardBody>
      </Card>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-fg">Recent conversations</h2>

        {sessions.loading && !sessions.data ? (
          <LoadingState />
        ) : sessions.error ? (
          <ErrorState message={sessions.error} onRetry={sessions.refetch} />
        ) : !sessions.data || sessions.data.items.length === 0 ? (
          <EmptyState
            title="No conversations yet"
            description="Start one above to begin a guided assessment."
          />
        ) : (
          <ul className="space-y-2">
            {sessions.data.items.map((session) => (
              <li key={session.id}>
                <Link href={`/agent/${session.id}`} className="block">
                  <Card className="transition-colors hover:border-primary/40">
                    <CardBody className="flex items-center justify-between gap-4 py-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium text-fg">
                            {session.title}
                          </span>
                          {session.is_archived && <Badge tone="neutral">Archived</Badge>}
                        </div>
                        <p className="mt-0.5 text-xs text-muted">
                          {countLabel(session.message_count, "message")} ·{" "}
                          {formatRelative(session.last_activity_at ?? session.created_at)}
                        </p>
                      </div>
                      <span className="shrink-0 text-xs text-primary">Open →</span>
                    </CardBody>
                  </Card>
                </Link>
              </li>
            ))}
          </ul>
        )}

        <InlineError message={null} />
      </section>
    </div>
  );
}
