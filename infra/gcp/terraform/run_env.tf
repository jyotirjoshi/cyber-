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
    CYNUX_ENVIRONMENT               = "production"
    CYNUX_DEBUG                     = "false"
    CYNUX_EXPOSE_API_DOCS           = "true"
    CYNUX_PUBLIC_BASE_URL           = local.firebase_url
    CYNUX_CORS_ORIGINS              = local.firebase_url
    CYNUX_ALLOWED_HOSTS             = "${var.project_id}.web.app,${var.project_id}.firebaseapp.com,cynux-api-${data.google_project.deployment.number}.${var.region}.run.app"
    CYNUX_STORAGE__ENDPOINT_URL     = "https://storage.googleapis.com"
    CYNUX_STORAGE__REGION           = var.region
    CYNUX_STORAGE__BUCKET           = google_storage_bucket.artifacts.name
    CYNUX_STORAGE__FORCE_PATH_STYLE = "false"
    CYNUX_STORAGE__SSE              = "AES256"
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
