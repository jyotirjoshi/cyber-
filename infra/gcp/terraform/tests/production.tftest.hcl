mock_provider "google" {}
mock_provider "google-beta" {}
mock_provider "random" {}

override_resource {
  target          = google_service_account.api
  override_during = plan
  values = {
    email = "cynux-api@cynux-security-test.iam.gserviceaccount.com"
  }
}

override_resource {
  target          = google_service_account.web
  override_during = plan
  values = {
    email = "cynux-web@cynux-security-test.iam.gserviceaccount.com"
  }
}

run "managed_foundation" {
  command = plan

  variables {
    project_id = "cynux-security-test"
    image_tag  = "deadbeef"
  }

  assert {
    condition     = google_sql_database_instance.cynux.deletion_protection
    error_message = "Cloud SQL must be deletion protected."
  }

  assert {
    condition     = google_sql_database_instance.cynux.settings[0].ip_configuration[0].ipv4_enabled == false
    error_message = "Cloud SQL must not expose a public IPv4 address."
  }

  assert {
    condition     = google_sql_database_instance.cynux.settings[0].backup_configuration[0].enabled && google_sql_database_instance.cynux.settings[0].backup_configuration[0].point_in_time_recovery_enabled
    error_message = "Cloud SQL backups and point-in-time recovery must be enabled."
  }

  assert {
    condition     = google_redis_instance.cynux.tier == "BASIC" && google_redis_instance.cynux.memory_size_gb == 1
    error_message = "Redis must begin on the cost-controlled 1 GiB BASIC tier."
  }

  assert {
    condition     = google_redis_instance.cynux.auth_enabled && google_redis_instance.cynux.transit_encryption_mode == "SERVER_AUTHENTICATION"
    error_message = "Redis must require AUTH and TLS."
  }

  assert {
    condition     = google_storage_bucket.artifacts.public_access_prevention == "enforced" && google_storage_bucket.artifacts.uniform_bucket_level_access
    error_message = "Artifact storage must prevent public access and use uniform IAM."
  }

  assert {
    condition     = google_storage_bucket.artifacts.versioning[0].enabled
    error_message = "Artifact storage must retain object versions."
  }

  assert {
    condition     = google_sql_database_instance.cynux.region == var.region && google_redis_instance.cynux.region == var.region && google_artifact_registry_repository.cynux.location == var.region
    error_message = "Stateful and image services must remain regionally colocated."
  }

  assert {
    condition = length(distinct([
      google_service_account.api.account_id,
      google_service_account.web.account_id,
      google_service_account.worker.account_id,
      google_service_account.defectdojo.account_id,
      google_service_account.build.account_id,
      google_service_account.storage.account_id,
    ])) == 6
    error_message = "Runtime, build, and HMAC identities must be separate."
  }

  assert {
    condition = alltrue([
      for binding in google_project_iam_member.runtime_roles :
      !contains(["roles/owner", "roles/editor"], binding.role)
    ])
    error_message = "Primitive Owner and Editor roles are forbidden."
  }

  assert {
    condition     = google_cloud_run_v2_service.api.template[0].scaling[0].min_instance_count == 0 && google_cloud_run_v2_service.api.template[0].scaling[0].max_instance_count <= 2
    error_message = "The API must scale to zero and cap instances at two initially."
  }

  assert {
    condition     = google_cloud_run_v2_service.api.template[0].timeout == "3600s" && google_cloud_run_v2_service.api.template[0].max_instance_request_concurrency <= 80
    error_message = "The API request timeout and concurrency must remain bounded."
  }

  assert {
    condition     = google_cloud_run_v2_service.api.template[0].service_account == "cynux-api@cynux-security-test.iam.gserviceaccount.com" && google_cloud_run_v2_service.web.template[0].service_account == "cynux-web@cynux-security-test.iam.gserviceaccount.com"
    error_message = "API and frontend must bind their separate service identities."
  }

  assert {
    condition     = google_cloud_run_v2_job.migrate.template[0].template[0].max_retries == 0 && google_cloud_run_v2_job.migrate.template[0].task_count == 1
    error_message = "Migrations must run once without retrying schema failures."
  }

  assert {
    condition     = google_cloud_run_v2_service.api.template[0].vpc_access[0].egress == "PRIVATE_RANGES_ONLY" && google_cloud_run_v2_job.migrate.template[0].template[0].vpc_access[0].egress == "PRIVATE_RANGES_ONLY"
    error_message = "API and migration traffic to data services must use direct VPC egress."
  }

  assert {
    condition = alltrue([
      for env in google_cloud_run_v2_service.api.template[0].containers[0].env :
      !can(regex("(?i)(PASSWORD|SECRET|KEY|TOKEN)", env.name)) || length(env.value_source) == 1
    ])
    error_message = "API credential environment variables must use Secret Manager references."
  }

  assert {
    condition = alltrue([
      for env in google_cloud_run_v2_job.migrate.template[0].template[0].containers[0].env :
      !can(regex("(?i)(PASSWORD|SECRET|KEY|TOKEN)", env.name)) || length(env.value_source) == 1
    ])
    error_message = "Migration credential environment variables must use Secret Manager references."
  }

  assert {
    condition     = length(google_cloud_run_v2_service.web.template[0].containers[0].env) == 0
    error_message = "The same-origin frontend must not receive runtime data-plane configuration or secrets."
  }
}
