locals {
  common_labels = merge({
    application = "cynux"
    environment = var.environment
    managed_by  = "terraform"
  }, var.labels)

  required_apis = toset([
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "redis.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
  ])
}

resource "google_project_service" "required" {
  for_each = local.required_apis

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_compute_network" "cynux" {
  name                    = "cynux-production"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required]
}

resource "google_compute_subnetwork" "cynux" {
  name                     = "cynux-${var.region}"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.cynux.id
  ip_cidr_range            = var.network_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.1
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_global_address" "private_service_range" {
  name          = "cynux-private-services"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.cynux.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.cynux.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range.name]

  depends_on = [google_project_service.required]
}

resource "google_compute_router" "cynux" {
  name    = "cynux-${var.region}"
  project = var.project_id
  region  = var.region
  network = google_compute_network.cynux.id
}

resource "google_compute_router_nat" "cynux" {
  name                               = "cynux-${var.region}"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.cynux.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.cynux.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_artifact_registry_repository" "cynux" {
  location      = var.region
  project       = var.project_id
  repository_id = "cynux"
  description   = "Immutable Cynux production container images"
  format        = "DOCKER"
  labels        = local.common_labels

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-old-untagged"
    action = "DELETE"

    condition {
      tag_state  = "UNTAGGED"
      older_than = "1209600s"
    }
  }

  depends_on = [google_project_service.required]
}
