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

variable "labels" {
  description = "Additional labels applied to supported resources."
  type        = map(string)
  default     = {}
}
