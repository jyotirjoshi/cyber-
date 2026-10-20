import type { IntegrationKind } from "./types";

export const BYOK_PROVIDERS = [
  { kind: "openai", label: "OpenAI" },
  { kind: "anthropic", label: "Anthropic" },
  { kind: "google", label: "Google" },
  { kind: "openrouter", label: "OpenRouter" },
] as const;

export const INTEGRATION_SETUP_HINTS = {
  servicenow: {
    config: '{"table":"incident","assignment_group":"Security Operations"}',
    credential: "api_token",
  },
  azure_devops: {
    config: '{"organization":"acme","project":"Security","work_item_type":"Issue"}',
    credential: "api_token",
  },
  linear: {
    config: '{"team_id":"your-linear-team-id"}',
    credential: "api_token",
  },
  pagerduty: {
    config: '{"source":"Cynux"}',
    credential: "routing_key",
  },
  splunk: {
    config: '{"index":"security","source":"cynux","sourcetype":"cynux:notification","host":"cynux"}',
    credential: "hec_token",
  },
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
  qualys: {
    config: '{"asset_ip":"203.0.113.10"}',
    credential: "username + password",
  },
  rapid7: {
    config: '{"asset_ids":["282"]}',
    credential: "username + password",
  },
  wiz: {
    config: '{"region":"us1","project_ids":["project-id"]}',
    credential: "client_id + client_secret",
  },
  prisma_cloud: {
    config: '{"cloud_account_ids":["123456789012"]}',
    credential: "access_key_id + secret_key",
  },
  crowdstrike: {
    config: "{}",
    credential: "client_id + client_secret",
  },
  aws_security_hub: {
    config: '{"region":"us-east-1","account_ids":["123456789012"]}',
    credential: "access_key_id + secret_access_key (optional session_token)",
  },
  aws_inspector: {
    config: '{"region":"us-east-1","account_ids":["123456789012"]}',
    credential: "access_key_id + secret_access_key (optional session_token)",
  },
  hackerone: {
    config: '{"program_handles":["acme"]}',
    credential: "api_username + api_token",
  },
  bugcrowd: {
    config: '{"engagement_codes":["acme-web"]}',
    credential: "token_username + token_password",
  },
  checkmarx: {
    config: '{"auth_url":"https://iam.checkmarx.net","tenant":"acme","projects":{"683c51da-8644-4e27-990f-1128ab911a1b":"acme/payments"}}',
    credential: "client_id + client_secret",
  },
  fortify: {
    config: '{"application_versions":{"42":"acme/payments"}}',
    credential: "automation_token",
  },
  azure_defender: {
    config: '{"subscription_id":"11111111-1111-1111-1111-111111111111"}',
    credential: "tenant_id + client_id + client_secret",
  },
  gcp_scc: {
    config: '{"project_id":"acme-prod","location":"global"}',
    credential: "service_account_json",
  },
  burp_dast: {
    config: '{"site_ids":["28"]}',
    credential: "api_key",
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
  zscaler: {
    config: '{"customer_id":"customer-id","audience":"https://api.zscaler.com","verify_tls":true}',
    credential: "client_id + client_secret",
  },
} as const;

export const ADDABLE_INTEGRATIONS: Array<{ kind: IntegrationKind; label: string }> = [
  { kind: "defectdojo", label: "DefectDojo" },
  { kind: "jira", label: "Jira" },
  { kind: "servicenow", label: "ServiceNow" },
  { kind: "azure_devops", label: "Azure DevOps" },
  { kind: "linear", label: "Linear" },
  { kind: "pagerduty", label: "PagerDuty" },
  { kind: "splunk", label: "Splunk HEC" },
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
  { kind: "qualys", label: "Qualys VM" },
  { kind: "rapid7", label: "Rapid7 InsightVM" },
  { kind: "wiz", label: "Wiz" },
  { kind: "prisma_cloud", label: "Prisma Cloud" },
  { kind: "crowdstrike", label: "CrowdStrike Falcon Spotlight" },
  { kind: "aws_security_hub", label: "AWS Security Hub" },
  { kind: "aws_inspector", label: "Amazon Inspector" },
  { kind: "hackerone", label: "HackerOne" },
  { kind: "bugcrowd", label: "Bugcrowd" },
  { kind: "checkmarx", label: "Checkmarx One" },
  { kind: "fortify", label: "Fortify SSC" },
  { kind: "azure_defender", label: "Microsoft Defender for Cloud" },
  { kind: "gcp_scc", label: "Google Security Command Center" },
  { kind: "burp_dast", label: "Burp Suite DAST" },
  { kind: "prowler_aws", label: "Prowler AWS account" },
  { kind: "prowler_azure", label: "Prowler Azure subscription" },
  { kind: "prowler_gcp", label: "Prowler GCP project" },
  { kind: "zscaler", label: "Zscaler Zero Trust Exchange" },
];
