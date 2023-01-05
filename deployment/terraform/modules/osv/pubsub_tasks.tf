# Pub/Sub worker tasks topics

resource "google_pubsub_topic" "tasks" {
  project = var.project_id
  name    = "tasks"

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "failed_tasks" {
  project = var.project_id
  name    = "failed-tasks"
}

resource "google_pubsub_subscription" "tasks" {
  project                    = var.project_id
  name                       = "tasks"
  topic                      = google_pubsub_topic.tasks.id
  message_retention_duration = "604800s"
  ack_deadline_seconds       = 600

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.failed_tasks.id
    max_delivery_attempts = 5
  }

  expiration_policy {
    ttl = "" # never expires
  }

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "pypi_bridge" {
  project = var.project_id
  name    = "pypi-bridge"
}

# Service account permissions
resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"
}

resource "google_pubsub_subscription_iam_member" "tasks_service_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.tasks.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

resource "google_pubsub_topic_iam_member" "failed_tasks_service_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.failed_tasks.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.pubsub.email}"
}
