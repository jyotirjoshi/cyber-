resource "random_password" "database" {
  length           = 40
  special          = true
  override_special = "-_~"
}

resource "random_password" "jwt" {
  length  = 64
  special = false
}

resource "random_id" "fernet" {
  byte_length = 32
}

resource "random_password" "defectdojo_admin" {
  length           = 36
  special          = true
  override_special = "-_~!"
}

resource "random_password" "defectdojo_secret" {
  length  = 64
  special = false
}

resource "random_password" "defectdojo_database" {
  length           = 40
  special          = true
  override_special = "-_~"
}

resource "random_password" "defectdojo_credential" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "cynux" {
  name                = "cynux-postgres"
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = var.sql_tier
    availability_type = "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = var.sql_disk_size_gb
    disk_autoresize   = true
    pricing_plan      = "PER_USE"
    user_labels       = local.common_labels

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.cynux.id
      enable_private_path_for_google_cloud_services = true
    }

    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_project_service.required,
    google_service_networking_connection.private_services,
  ]
}

resource "google_sql_database" "cynux" {
  name     = "cynux"
  project  = var.project_id
  instance = google_sql_database_instance.cynux.name
}

resource "google_sql_user" "cynux" {
  name     = "cynux"
  project  = var.project_id
  instance = google_sql_database_instance.cynux.name
  password = random_password.database.result
}

resource "google_redis_instance" "cynux" {
  name                    = "cynux-redis"
  project                 = var.project_id
  region                  = var.region
  location_id             = var.zone
  tier                    = "BASIC"
  memory_size_gb          = 1
  redis_version           = "REDIS_7_2"
  authorized_network      = google_compute_network.cynux.id
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  reserved_ip_range       = google_compute_global_address.private_service_range.name
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  labels                  = local.common_labels
  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 4
        minutes = 0
        seconds = 0
        nanos   = 0
      }
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_project_service.required,
    google_service_networking_connection.private_services,
  ]
}

resource "google_storage_bucket" "artifacts" {
  name                        = "${var.project_id}-cynux-artifacts"
  project                     = var.project_id
  location                    = upper(var.region)
  storage_class               = "STANDARD"
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = local.common_labels

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      days_since_noncurrent_time = 30
      num_newer_versions         = 3
    }
  }

  lifecycle_rule {
    action {
      type = "AbortIncompleteMultipartUpload"
    }
    condition {
      age = 7
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required]
}

resource "google_storage_hmac_key" "artifacts" {
  project               = var.project_id
  service_account_email = google_service_account.storage.email
}

locals {
  secret_payloads = {
    database-url                 = "postgresql+asyncpg://cynux:${urlencode(random_password.database.result)}@${google_sql_database_instance.cynux.private_ip_address}:5432/${google_sql_database.cynux.name}"
    database-password            = random_password.database.result
    redis-url                    = "rediss://:${urlencode(google_redis_instance.cynux.auth_string)}@${google_redis_instance.cynux.host}:${google_redis_instance.cynux.port}/0"
    gcs-access-key               = google_storage_hmac_key.artifacts.access_id
    gcs-secret-key               = google_storage_hmac_key.artifacts.secret
    jwt-secret                   = random_password.jwt.result
    fernet-key                   = random_id.fernet.b64_url
    defectdojo-admin-password    = random_password.defectdojo_admin.result
    defectdojo-secret-key        = random_password.defectdojo_secret.result
    defectdojo-database-password = random_password.defectdojo_database.result
    defectdojo-credential-key    = random_password.defectdojo_credential.result
  }

  secret_access_pairs = {
    api_database      = { account = "api", secret = "database-url" }
    api_redis         = { account = "api", secret = "redis-url" }
    api_jwt           = { account = "api", secret = "jwt-secret" }
    api_fernet        = { account = "api", secret = "fernet-key" }
    api_gcs_access    = { account = "api", secret = "gcs-access-key" }
    api_gcs_secret    = { account = "api", secret = "gcs-secret-key" }
    worker_database   = { account = "worker", secret = "database-url" }
    worker_redis      = { account = "worker", secret = "redis-url" }
    worker_fernet     = { account = "worker", secret = "fernet-key" }
    worker_gcs_access = { account = "worker", secret = "gcs-access-key" }
    worker_gcs_secret = { account = "worker", secret = "gcs-secret-key" }
    dojo_admin        = { account = "defectdojo", secret = "defectdojo-admin-password" }
    dojo_secret       = { account = "defectdojo", secret = "defectdojo-secret-key" }
    dojo_database     = { account = "defectdojo", secret = "defectdojo-database-password" }
    dojo_credential   = { account = "defectdojo", secret = "defectdojo-credential-key" }
  }
}

resource "google_secret_manager_secret" "cynux" {
  for_each = local.secret_payloads

  project   = var.project_id
  secret_id = "cynux-${each.key}"
  labels    = local.common_labels

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "cynux" {
  for_each = local.secret_payloads

  secret      = google_secret_manager_secret.cynux[each.key].id
  secret_data = each.value
}

resource "google_secret_manager_secret_iam_member" "accessors" {
  for_each = local.secret_access_pairs

  project   = var.project_id
  secret_id = google_secret_manager_secret.cynux[each.value.secret].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.service_account_emails[each.value.account]}"
}

resource "google_secret_manager_secret" "defectdojo_api_token" {
  project   = var.project_id
  secret_id = "cynux-defectdojo-api-token"
  labels    = local.common_labels

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_iam_member" "defectdojo_can_publish_api_token" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.defectdojo_api_token.secret_id
  role      = "roles/secretmanager.secretVersionAdder"
  member    = "serviceAccount:${google_service_account.defectdojo.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_can_read_defectdojo_api_token" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.defectdojo_api_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker.email}"
}
