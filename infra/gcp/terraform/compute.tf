locals {
  ubuntu_image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"

  scanner_bootstrap = templatefile("${path.module}/../templates/scanner-cloud-init.yaml.tftpl", {
    project_id              = var.project_id
    region                  = var.region
    backend_image           = local.backend_image
    database_host           = google_sql_database_instance.cynux.private_ip_address
    database_name           = google_sql_database.cynux.name
    database_user           = google_sql_user.cynux.name
    artifact_bucket         = google_storage_bucket.artifacts.name
    defectdojo_private_url  = "http://${google_compute_address.defectdojo.address}:8080"
    defectdojo_token_secret = google_secret_manager_secret.defectdojo_api_token.secret_id
  })

  defectdojo_compose = templatefile("${path.module}/../templates/defectdojo-compose.yml.tftpl", {
    defectdojo_version = var.defectdojo_version
    private_ip         = google_compute_address.defectdojo.address
  })

  defectdojo_bootstrap = templatefile("${path.module}/../templates/defectdojo-cloud-init.yaml.tftpl", {
    project_id       = var.project_id
    compose_b64      = base64encode(local.defectdojo_compose)
    api_token_secret = google_secret_manager_secret.defectdojo_api_token.secret_id
    private_ip       = google_compute_address.defectdojo.address
  })
}

resource "google_compute_firewall" "iap_ssh" {
  name      = "cynux-allow-iap-ssh"
  project   = var.project_id
  network   = google_compute_network.cynux.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["cynux-admin"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "private_defectdojo" {
  name      = "cynux-allow-private-defectdojo"
  project   = var.project_id
  network   = google_compute_network.cynux.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = [var.network_cidr]
  target_tags   = ["cynux-defectdojo"]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_address" "defectdojo" {
  name         = "cynux-defectdojo-01"
  project      = var.project_id
  region       = var.region
  subnetwork   = google_compute_subnetwork.cynux.id
  address_type = "INTERNAL"
}

resource "google_compute_resource_policy" "defectdojo_snapshots" {
  name    = "cynux-defectdojo-daily-snapshots"
  project = var.project_id
  region  = var.region

  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "01:00"
      }
    }

    retention_policy {
      max_retention_days    = 7
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }

    snapshot_properties {
      storage_locations = [var.region]
      guest_flush       = true
      labels            = local.common_labels
    }
  }
}

resource "google_compute_disk" "defectdojo_data" {
  name                      = "cynux-defectdojo-data"
  project                   = var.project_id
  zone                      = var.zone
  type                      = "pd-balanced"
  size                      = 50
  physical_block_size_bytes = 4096
  labels                    = local.common_labels
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_disk_resource_policy_attachment" "defectdojo_snapshots" {
  name    = google_compute_resource_policy.defectdojo_snapshots.name
  project = var.project_id
  zone    = var.zone
  disk    = google_compute_disk.defectdojo_data.name
}

resource "google_compute_instance" "defectdojo" {
  name                      = "cynux-defectdojo-01"
  project                   = var.project_id
  zone                      = var.zone
  machine_type              = "e2-standard-2"
  desired_status            = "TERMINATED"
  allow_stopping_for_update = true
  deletion_protection       = true
  can_ip_forward            = false
  tags                      = ["cynux-admin", "cynux-defectdojo"]
  labels                    = local.common_labels

  boot_disk {
    auto_delete = false
    initialize_params {
      image  = local.ubuntu_image
      size   = 30
      type   = "pd-balanced"
      labels = local.common_labels
    }
  }

  attached_disk {
    source      = google_compute_disk.defectdojo_data.id
    device_name = "defectdojo-data"
    mode        = "READ_WRITE"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.cynux.id
    network_ip = google_compute_address.defectdojo.address
  }

  service_account {
    email  = google_service_account.defectdojo.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
    user-data              = local.defectdojo_bootstrap
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  depends_on = [
    google_compute_router_nat.cynux,
    google_secret_manager_secret_iam_member.accessors,
    google_secret_manager_secret_iam_member.defectdojo_can_publish_api_token,
  ]
}

resource "google_compute_instance" "scanner" {
  name                      = "cynux-scanner-01"
  project                   = var.project_id
  zone                      = var.zone
  machine_type              = "e2-standard-4"
  desired_status            = "TERMINATED"
  allow_stopping_for_update = true
  deletion_protection       = true
  can_ip_forward            = false
  tags                      = ["cynux-admin", "cynux-scanner"]
  labels                    = local.common_labels

  boot_disk {
    auto_delete = false
    initialize_params {
      image  = local.ubuntu_image
      size   = 40
      type   = "pd-balanced"
      labels = local.common_labels
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.cynux.id
  }

  service_account {
    email  = google_service_account.worker.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
    user-data              = local.scanner_bootstrap
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  depends_on = [
    google_compute_instance.defectdojo,
    google_compute_router_nat.cynux,
    google_secret_manager_secret_iam_member.accessors,
    google_secret_manager_secret_iam_member.worker_can_read_defectdojo_api_token,
  ]
}
