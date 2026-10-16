locals {
  multi_agent_alert_events = {
    task_runtime_unavailable = {
      event       = "worker.task_runtime_unavailable"
      display     = "Cynux multi-agent task runtime unavailable"
      severity    = "critical"
      description = "A durable task could not run because the worker runtime was unavailable."
    }
    stale_lease_recovered = {
      event       = "worker.agent_task_leases_recovered"
      display     = "Cynux multi-agent stale lease recovered"
      severity    = "warning"
      description = "One or more expired task leases required generation-fenced recovery."
    }
    queue_latency_high = {
      event       = "worker.agent_task_queue_latency_high"
      display     = "Cynux multi-agent queue latency high"
      severity    = "warning"
      description = "A durable task waited longer than the configured queue-latency ceiling."
    }
    task_dispatch_failed = {
      event       = "worker.task_dispatch_failed"
      display     = "Cynux multi-agent task dispatch failed"
      severity    = "critical"
      description = "An unhandled task dispatch error left a Redis entry pending for recovery."
    }
  }
}

resource "google_logging_metric" "multi_agent_events" {
  for_each = local.multi_agent_alert_events

  project     = var.project_id
  name        = "cynux_multi_agent_${each.key}"
  description = each.value.description
  filter      = "resource.type=\"gce_instance\" AND jsonPayload.event=\"${each.value.event}\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

  depends_on = [google_project_service.required]
}

resource "google_monitoring_alert_policy" "multi_agent_events" {
  for_each = local.multi_agent_alert_events

  project      = var.project_id
  display_name = each.value.display
  combiner     = "OR"
  enabled      = true
  severity     = each.value.severity == "critical" ? "CRITICAL" : "WARNING"

  documentation {
    content   = each.value.description
    mime_type = "text/markdown"
  }

  conditions {
    display_name = each.value.display

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.multi_agent_events[each.key].name}\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }

      trigger {
        count = 1
      }
    }
  }

  user_labels = merge(local.common_labels, {
    component = "multi-agent"
    severity  = each.value.severity
  })

  depends_on = [google_project_service.required]
}
