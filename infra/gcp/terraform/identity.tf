locals {
  service_accounts = {
    api = {
      account_id   = "cynux-api"
      display_name = "Cynux API runtime"
    }
    web = {
      account_id   = "cynux-web"
      display_name = "Cynux frontend runtime"
    }
    worker = {
      account_id   = "cynux-worker"
      display_name = "Cynux isolated scanner worker"
    }
    defectdojo = {
      account_id   = "cynux-defectdojo"
      display_name = "Cynux DefectDojo runtime"
    }
    build = {
      account_id   = "cynux-build"
      display_name = "Cynux Cloud Build"
    }
    storage = {
      account_id   = "cynux-storage"
      display_name = "Cynux GCS HMAC identity"
    }
  }

  runtime_project_role_pairs = {
    api_cloudsql     = { account = "api", role = "roles/cloudsql.client" }
    api_logs         = { account = "api", role = "roles/logging.logWriter" }
    api_metrics      = { account = "api", role = "roles/monitoring.metricWriter" }
    web_logs         = { account = "web", role = "roles/logging.logWriter" }
    web_metrics      = { account = "web", role = "roles/monitoring.metricWriter" }
    worker_cloudsql  = { account = "worker", role = "roles/cloudsql.client" }
    worker_logs      = { account = "worker", role = "roles/logging.logWriter" }
    worker_metrics   = { account = "worker", role = "roles/monitoring.metricWriter" }
    worker_ar_reader = { account = "worker", role = "roles/artifactregistry.reader" }
    dojo_logs        = { account = "defectdojo", role = "roles/logging.logWriter" }
    dojo_metrics     = { account = "defectdojo", role = "roles/monitoring.metricWriter" }
    dojo_ar_reader   = { account = "defectdojo", role = "roles/artifactregistry.reader" }
    build_ar_writer  = { account = "build", role = "roles/artifactregistry.writer" }
    build_logs       = { account = "build", role = "roles/logging.logWriter" }
  }
}

resource "google_service_account" "api" {
  project      = var.project_id
  account_id   = local.service_accounts.api.account_id
  display_name = local.service_accounts.api.display_name
}

resource "google_service_account" "web" {
  project      = var.project_id
  account_id   = local.service_accounts.web.account_id
  display_name = local.service_accounts.web.display_name
}

resource "google_service_account" "worker" {
  project      = var.project_id
  account_id   = local.service_accounts.worker.account_id
  display_name = local.service_accounts.worker.display_name
}

resource "google_service_account" "defectdojo" {
  project      = var.project_id
  account_id   = local.service_accounts.defectdojo.account_id
  display_name = local.service_accounts.defectdojo.display_name
}

resource "google_service_account" "build" {
  project      = var.project_id
  account_id   = local.service_accounts.build.account_id
  display_name = local.service_accounts.build.display_name
}

resource "google_service_account" "storage" {
  project      = var.project_id
  account_id   = local.service_accounts.storage.account_id
  display_name = local.service_accounts.storage.display_name
}

locals {
  service_account_emails = {
    api        = google_service_account.api.email
    web        = google_service_account.web.email
    worker     = google_service_account.worker.email
    defectdojo = google_service_account.defectdojo.email
    build      = google_service_account.build.email
    storage    = google_service_account.storage.email
  }
}

resource "google_project_iam_member" "runtime_roles" {
  for_each = local.runtime_project_role_pairs

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${local.service_account_emails[each.value.account]}"
}

resource "google_storage_bucket_iam_member" "artifact_objects" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.storage.email}"
}

resource "google_service_account_iam_member" "worker_can_use_storage_identity" {
  service_account_id = google_service_account.storage.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.worker.email}"
}
