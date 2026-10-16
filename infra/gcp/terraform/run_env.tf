data "google_project" "deployment" {
  project_id = var.project_id
}

locals {
  backend_image  = "${var.region}-docker.pkg.dev/${var.project_id}/cynux/api:${var.image_tag}"
  frontend_image = "${var.region}-docker.pkg.dev/${var.project_id}/cynux/frontend:${var.image_tag}"
  firebase_url   = "https://${var.project_id}.web.app"

  database_env = {
    CYNUX_DB__HOST         = google_sql_database_instance.cynux.private_ip_address
    CYNUX_DB__PORT         = "5432"
    CYNUX_DB__NAME         = google_sql_database.cynux.name
    CYNUX_DB__USER         = google_sql_user.cynux.name
    CYNUX_DB__POOL_SIZE    = "3"
    CYNUX_DB__MAX_OVERFLOW = "2"
  }

  api_env = merge(local.database_env, {
    CYNUX_ENVIRONMENT                                 = "production"
    CYNUX_DEBUG                                       = "false"
    CYNUX_EXPOSE_API_DOCS                             = "true"
    CYNUX_PUBLIC_BASE_URL                             = local.firebase_url
    CYNUX_CORS_ORIGINS                                = local.firebase_url
    CYNUX_ALLOWED_HOSTS                               = "${var.project_id}.web.app,${var.project_id}.firebaseapp.com,cynux-api-${data.google_project.deployment.number}.${var.region}.run.app,*.a.run.app,*.${var.region}.run.app"
    CYNUX_STORAGE__ENDPOINT_URL                       = "https://storage.googleapis.com"
    CYNUX_STORAGE__REGION                             = var.region
    CYNUX_STORAGE__BUCKET                             = google_storage_bucket.artifacts.name
    CYNUX_STORAGE__FORCE_PATH_STYLE                   = "false"
    CYNUX_STORAGE__SSE                                = "AES256"
    CYNUX_FEATURES__CUSTOM_AGENTS                     = "true"
    CYNUX_FEATURES__INTERNAL_KNOWLEDGE                = "true"
    CYNUX_FEATURES__MULTI_AGENT                       = tostring(var.multi_agent_enabled)
    CYNUX_FEATURES__MULTI_AGENT_CANARY_ORG_IDS        = join(",", var.multi_agent_canary_org_ids)
    CYNUX_AGENT__MULTI_AGENT_MAX_TASKS                = "30"
    CYNUX_AGENT__MULTI_AGENT_MAX_DEPTH                = "3"
    CYNUX_AGENT__MULTI_AGENT_MAX_PARALLEL_TASKS       = "3"
    CYNUX_AGENT__MULTI_AGENT_DEFAULT_RUNTIME_SECONDS  = "7200"
    CYNUX_AGENT__MULTI_AGENT_DECISION_WAVES           = "3"
    CYNUX_AGENT__MULTI_AGENT_MAX_TOOL_CALLS           = "20"
    CYNUX_AGENT__MULTI_AGENT_MAX_INPUT_TOKENS         = "100000"
    CYNUX_AGENT__MULTI_AGENT_MAX_OUTPUT_TOKENS        = "20000"
    CYNUX_AGENT__MULTI_AGENT_MAX_SPEND_MICROS         = "1000000"
    CYNUX_AGENT__TASK_RESERVATION_TTL_SECONDS         = "900"
    CYNUX_AGENT__TASK_LEASE_SECONDS                   = "90"
    CYNUX_AGENT__STALE_LEASE_ALERT_SECONDS            = "180"
    CYNUX_AGENT__QUEUE_LATENCY_ALERT_SECONDS          = "120"
    CYNUX_AGENT__WORKER_MAX_CONCURRENCY               = tostring(var.multi_agent_worker_concurrency)
    CYNUX_AGENT__PROVIDER_MAX_PARALLEL_TASKS          = jsonencode(var.multi_agent_provider_parallelism)
    CYNUX_KNOWLEDGE__INDEXING_CONCURRENCY             = "2"
    CYNUX_KNOWLEDGE__MAX_UPLOAD_BYTES                 = "20971520"
    CYNUX_KNOWLEDGE__MAX_DOCUMENT_TOKENS              = "500000"
    CYNUX_KNOWLEDGE__MAX_DOCUMENTS_PER_COLLECTION     = "200"
    CYNUX_KNOWLEDGE__MAX_STORAGE_BYTES_PER_COLLECTION = "209715200"
    CYNUX_KNOWLEDGE__DEFAULT_EMBEDDING_PROVIDER       = "openai"
    CYNUX_KNOWLEDGE__DEFAULT_EMBEDDING_MODEL          = "text-embedding-3-small"
  })

  api_secret_env = {
    CYNUX_DB__PASSWORD                        = "database-password"
    CYNUX_REDIS__URL                          = "redis-url"
    CYNUX_SECURITY__JWT_SECRET                = "jwt-secret"
    CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY = "fernet-key"
    CYNUX_STORAGE__ACCESS_KEY_ID              = "gcs-access-key"
    CYNUX_STORAGE__SECRET_ACCESS_KEY          = "gcs-secret-key"
  }

  migration_secret_env = {
    CYNUX_DB__PASSWORD = "database-password"
  }
}
