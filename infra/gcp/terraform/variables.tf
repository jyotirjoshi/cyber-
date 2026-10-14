variable "project_id" {
  description = "Dedicated Firebase-linked Google Cloud project ID."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project ID."
  }
}

variable "region" {
  description = "Primary region for all regional services."
  type        = string
  default     = "asia-south1"
}

variable "zone" {
  description = "Primary zone for zonal resources."
  type        = string
  default     = "asia-south1-a"

  validation {
    condition     = startswith(var.zone, "${var.region}-")
    error_message = "zone must belong to region."
  }
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
  default     = "production"
}

variable "image_tag" {
  description = "Immutable git-derived tag shared by backend and frontend release images."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{6,127}$", var.image_tag)) && lower(var.image_tag) != "latest"
    error_message = "image_tag must be an immutable tag of at least seven characters and cannot be latest."
  }
}

variable "migration_image_tag" {
  description = "Optional immutable migration-only repair image; empty uses the application release."
  type        = string
  default     = ""
  validation {
    condition     = var.migration_image_tag == "" || (can(regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{6,127}$", var.migration_image_tag)) && lower(var.migration_image_tag) != "latest")
    error_message = "Migration repair tags must be immutable and cannot be latest."
  }
}

variable "network_cidr" {
  description = "RFC1918 subnet used by private application resources."
  type        = string
  default     = "10.42.0.0/20"

  validation {
    condition     = can(cidrhost(var.network_cidr, 1))
    error_message = "network_cidr must be valid CIDR notation."
  }
}

variable "sql_tier" {
  description = "Initial cost-controlled Cloud SQL tier; increase before sustained production traffic."
  type        = string
  default     = "db-f1-micro"
}

variable "sql_disk_size_gb" {
  description = "Initial Cloud SQL SSD size."
  type        = number
  default     = 10

  validation {
    condition     = var.sql_disk_size_gb >= 10
    error_message = "Cloud SQL requires at least 10 GiB."
  }
}

variable "scanner_boot_disk_size_gb" {
  description = "Scanner worker boot disk capacity for pinned tool images and transient assessment artifacts."
  type        = number
  default     = 100

  validation {
    condition     = var.scanner_boot_disk_size_gb >= 80
    error_message = "The scanner worker needs at least 80 GiB for the production toolchain."
  }
}

variable "defectdojo_version" {
  description = "Pinned upstream DefectDojo Open Source release tag."
  type        = string
  default     = "3.3.300"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.defectdojo_version))
    error_message = "defectdojo_version must be a pinned semantic release tag."
  }
}

variable "labels" {
  description = "Additional labels applied to supported resources."
  type        = map(string)
  default     = {}
}
