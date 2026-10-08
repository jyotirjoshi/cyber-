import type { IntegrationKind } from "./types";

export const BYOK_PROVIDERS = [
  { kind: "openai", label: "OpenAI" },
  { kind: "anthropic", label: "Anthropic" },
  { kind: "google", label: "Google" },
  { kind: "openrouter", label: "OpenRouter" },
] as const;

export const INTEGRATION_SETUP_HINTS = {
  sonarqube: {
    config: '{"project_keys":["my-project"]}',
    credential: "api_token",
  },
  snyk: {
    config: '{"organization_id":"11111111-1111-4111-8111-111111111111"}',
    credential: "api_token",
  },
  tenable: {
    config: '{"scan_ids":["11111111-1111-4111-8111-111111111111"]}',
    credential: "access_key + secret_key",
  },
  bitbucket: {
    config: '{"account_email":"security@example.com","workspace":"my-workspace","repository":"my-repo"}',
    credential: "api_token",
  },
  prowler_aws: {
    config: '{"account_id":"123456789012"}',
    credential: "access_key_id + secret_access_key (optional session_token)",
  },
  prowler_azure: {
    config: '{"account_id":"11111111-1111-1111-1111-111111111111"}',
    credential: "client_id + tenant_id + client_secret",
  },
  prowler_gcp: {
    config: '{"account_id":"example-project-1"}',
    credential: "service_account_json",
  },
} as const;

export const ADDABLE_INTEGRATIONS: Array<{ kind: IntegrationKind; label: string }> = [
  { kind: "defectdojo", label: "DefectDojo" },
  { kind: "jira", label: "Jira" },
  { kind: "slack", label: "Slack" },
  { kind: "email", label: "SMTP email" },
  { kind: "dify", label: "Dify knowledge base" },
  { kind: "misp", label: "MISP" },
  { kind: "nvd", label: "NVD" },
  { kind: "github", label: "GitHub" },
  { kind: "gitlab", label: "GitLab" },
  { kind: "bitbucket", label: "Bitbucket" },
  { kind: "wazuh", label: "Wazuh" },
  { kind: "sonarqube", label: "SonarQube" },
  { kind: "snyk", label: "Snyk" },
  { kind: "tenable", label: "Tenable VM" },
  { kind: "prowler_aws", label: "Prowler AWS account" },
  { kind: "prowler_azure", label: "Prowler Azure subscription" },
  { kind: "prowler_gcp", label: "Prowler GCP project" },
];
