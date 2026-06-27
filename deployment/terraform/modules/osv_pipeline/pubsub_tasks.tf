# Pub/Sub worker tasks topics

resource "google_pubsub_topic" "tasks" {
  project = var.project_id
  name    = var.pubsub_topic_name

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "failed_tasks" {
  project = var.project_id
  name    = var.pubsub_topic_failed_tasks_name
}

resource "google_pubsub_subscription" "default_work" {
  project                    = var.project_id
  name                       = var.pubsub_subscription_default_work_pool_name
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

  filter = "attributes.work_pool = \"default\""
}

resource "google_pubsub_subscription" "work_pools" {
  for_each                   = toset(var.extra_work_pools)
  project                    = var.project_id
  name                       = each.value
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

  filter = "attributes.work_pool = \"${each.value}\""
}

# Dead Letter Queue (DLQ) permissions
# Pub/Sub requires its system service account to have publisher rights on the DLQ
# topic and subscriber rights on the subscriptions to forward failing tasks.

# Pub/Sub system service identity for this project
resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"
}

# Allow Pub/Sub to pull/acknowledge messages from the default subscription
resource "google_pubsub_subscription_iam_member" "default_work_service_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.default_work.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

# Allow Pub/Sub to pull/acknowledge messages from the dynamic work pool subscriptions
resource "google_pubsub_subscription_iam_member" "work_pools_service_subscriber" {
  for_each     = toset(var.extra_work_pools)
  project      = var.project_id
  subscription = google_pubsub_subscription.work_pools[each.value].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

# Allow Pub/Sub to publish failed tasks to the DLQ failed-tasks topic
resource "google_pubsub_topic_iam_member" "failed_tasks_service_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.failed_tasks.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.pubsub.email}"
}


resource "google_pubsub_subscription" "recovery" {
  project                    = var.project_id
  name                       = var.pubsub_subscription_recovery_name
  topic                      = google_pubsub_topic.failed_tasks.id
  message_retention_duration = "604800s" # 7 days
  ack_deadline_seconds       = 600

  expiration_policy {
    ttl = "" # never expires
  }
}