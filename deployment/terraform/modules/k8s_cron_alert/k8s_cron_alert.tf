variable "project_id" {
  type        = string
  description = "The project to create the alert policy in."
}

variable "cronjob_name" {
  type        = string
  description = "Name of the kubernetes cronjob to monitor."
}

variable "cronjob_expected_latency_minutes" {
  type        = number
  description = "Expected amount of time since last successful run of the job expressed in minutes."
}

variable "notification_channel" {
  type        = string
  description = "(Optional) The notification channel to send alerts to."
  default     = null
}

resource "google_monitoring_alert_policy" "cron_alert_policy" {
  project      = var.project_id
  display_name = "Cronjob: ${var.cronjob_name} has not run recently."
  combiner     = "OR"
  conditions {
    display_name = "Cronjob: ${var.cronjob_name} has not run recently."
    condition_prometheus_query_language {
      query               = "((time() - kube_cronjob_status_last_successful_time{cronjob=\"${var.cronjob_name}\"})/60) > ${var.cronjob_expected_latency_minutes}"
      duration            = "60s"
      evaluation_interval = "60s"
      alert_rule          = "AlwaysOn"
      rule_group          = "cronjob ${var.cronjob_name}"
    }
  }

  notification_channels = var.notification_channel != null ? toset([var.notification_channel]) : toset([])
  severity              = "ERROR"
}
