# Migration of pipeline resources from module.osv_test to module.osv_pipeline

# Datastore & Storage
moved {
  from = module.osv_test.google_firestore_database.datastore
  to   = module.osv_pipeline.google_firestore_database.datastore
}

moved {
  from = module.osv_test.google_storage_bucket.osv_vulnerabilities_export
  to   = module.osv_pipeline.google_storage_bucket.osv_vulnerabilities_export
}

moved {
  from = module.osv_test.google_storage_bucket.affected_commits_backups_bucket
  to   = module.osv_pipeline.google_storage_bucket.affected_commits_backups_bucket
}


# Pub/Sub
moved {
  from = module.osv_test.google_pubsub_topic.tasks
  to   = module.osv_pipeline.google_pubsub_topic.tasks
}

moved {
  from = module.osv_test.google_pubsub_topic.failed_tasks
  to   = module.osv_pipeline.google_pubsub_topic.failed_tasks
}

moved {
  from = module.osv_test.google_pubsub_subscription.default_work
  to   = module.osv_pipeline.google_pubsub_subscription.default_work
}

moved {
  from = module.osv_test.google_pubsub_subscription.work_pools
  to   = module.osv_pipeline.google_pubsub_subscription.work_pools
}

moved {
  from = module.osv_test.google_project_service_identity.pubsub
  to   = module.osv_pipeline.google_project_service_identity.pubsub
}

moved {
  from = module.osv_test.google_pubsub_subscription_iam_member.default_work_service_subscriber
  to   = module.osv_pipeline.google_pubsub_subscription_iam_member.default_work_service_subscriber
}

moved {
  from = module.osv_test.google_pubsub_topic_iam_member.failed_tasks_service_publisher
  to   = module.osv_pipeline.google_pubsub_topic_iam_member.failed_tasks_service_publisher
}

moved {
  from = module.osv_test.google_pubsub_subscription.recovery
  to   = module.osv_pipeline.google_pubsub_subscription.recovery
}

moved {
  from = module.osv_test.google_pubsub_subscription_iam_member.recovery_service_subscriber
  to   = module.osv_pipeline.google_pubsub_subscription_iam_member.recovery_service_subscriber
}
