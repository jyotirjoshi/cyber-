output "project_id" {
  value = var.project_id
}

output "region" {
  value = var.region
}

output "network_id" {
  value = google_compute_network.cynux.id
}

output "subnetwork_id" {
  value = google_compute_subnetwork.cynux.id
}

output "artifact_repository" {
  value = google_artifact_registry_repository.cynux.id
}

output "artifact_bucket_name" {
  value = google_storage_bucket.artifacts.name
}

output "sql_instance_name" {
  value = google_sql_database_instance.cynux.name
}

output "sql_connection_name" {
  value = google_sql_database_instance.cynux.connection_name
}

output "redis_endpoint" {
  value = {
    host = google_redis_instance.cynux.host
    port = google_redis_instance.cynux.port
  }
}

output "runtime_service_accounts" {
  value = {
    api        = google_service_account.api.email
    web        = google_service_account.web.email
    worker     = google_service_account.worker.email
    defectdojo = google_service_account.defectdojo.email
    build      = google_service_account.build.email
  }
}

output "secret_resource_ids" {
  value = {
    for name, resource in google_secret_manager_secret.cynux : name => resource.id
  }
}

output "api_service_uri" {
  value = google_cloud_run_v2_service.api.uri
}

output "web_service_uri" {
  value = google_cloud_run_v2_service.web.uri
}

output "migration_job_name" {
  value = google_cloud_run_v2_job.migrate.name
}
