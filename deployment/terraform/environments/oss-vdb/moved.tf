# Migration of pipeline resources from module.osv to module.osv_pipeline

# Datastore & Storage
moved {
  from = module.osv.google_firestore_database.datastore
  to   = module.osv_pipeline.google_firestore_database.datastore
}

moved {
  from = module.osv.google_storage_bucket.osv_vulnerabilities_export
  to   = module.osv_pipeline.google_storage_bucket.osv_vulnerabilities_export
}

moved {
  from = module.osv.google_storage_bucket.affected_commits_backups_bucket
  to   = module.osv_pipeline.google_storage_bucket.affected_commits_backups_bucket
}


moved {
  from = module.osv.google_compute_subnetwork.oss_fuzz_subnet[0]
  to   = module.osv_pipeline.google_compute_subnetwork.oss_fuzz_subnet[0]
}

# Pub/Sub
moved {
  from = module.osv.google_pubsub_topic.tasks
  to   = module.osv_pipeline.google_pubsub_topic.tasks
}

moved {
  from = module.osv.google_pubsub_topic.failed_tasks
  to   = module.osv_pipeline.google_pubsub_topic.failed_tasks
}

moved {
  from = module.osv.google_pubsub_subscription.default_work
  to   = module.osv_pipeline.google_pubsub_subscription.default_work
}

moved {
  from = module.osv.google_pubsub_subscription.work_pools
  to   = module.osv_pipeline.google_pubsub_subscription.work_pools
}

moved {
  from = module.osv.google_project_service_identity.pubsub
  to   = module.osv_pipeline.google_project_service_identity.pubsub
}

moved {
  from = module.osv.google_pubsub_subscription_iam_member.default_work_service_subscriber
  to   = module.osv_pipeline.google_pubsub_subscription_iam_member.default_work_service_subscriber
}

moved {
  from = module.osv.google_pubsub_topic_iam_member.failed_tasks_service_publisher
  to   = module.osv_pipeline.google_pubsub_topic_iam_member.failed_tasks_service_publisher
}

moved {
  from = module.osv.google_pubsub_subscription.recovery
  to   = module.osv_pipeline.google_pubsub_subscription.recovery
}

moved {
  from = module.osv.google_pubsub_subscription_iam_member.recovery_service_subscriber
  to   = module.osv_pipeline.google_pubsub_subscription_iam_member.recovery_service_subscriber
}

# Migration of API resources from module.osv to module.osv_api
moved {
  from = module.osv.google_cloud_run_service.api_backend
  to   = module.osv_api.google_cloud_run_service.api_backend
}

moved {
  from = module.osv.google_cloud_run_v2_service.api_backend_batch
  to   = module.osv_api.google_cloud_run_v2_service.api_backend_batch
}

moved {
  from = module.osv.google_endpoints_service.grpc_service
  to   = module.osv_api.google_endpoints_service.grpc_service
}

moved {
  from = module.osv.google_project_service.grpc_service_api
  to   = module.osv_api.google_project_service.grpc_service_api
}

moved {
  from = module.osv.null_resource.grpc_proxy_image
  to   = module.osv_api.null_resource.grpc_proxy_image
}

moved {
  from = module.osv.google_cloud_run_service.api
  to   = module.osv_api.google_cloud_run_service.api
}

moved {
  from = module.osv.google_cloud_run_domain_mapping.api
  to   = module.osv_api.google_cloud_run_domain_mapping.api
}

# Production CI/CD deployment SA and legacy Default Compute SA bindings moved out of shared modules
moved {
  from = module.osv.google_service_account.deployment_service
  to   = google_service_account.deployment_service
}

moved {
  from = module.osv.google_project_iam_member.deployment_service
  to   = google_project_iam_member.deployment_service
}

moved {
  from = module.osv.google_project_iam_member.compute_service
  to   = google_project_iam_member.compute_service
}

moved {
  from = module.osv.google_project_iam_member.compute_service_datastore
  to   = google_project_iam_member.compute_service_datastore
}

moved {
  from = module.osv.google_project_iam_member.website_secret_accessor
  to   = google_project_iam_member.website_secret_accessor
}

moved {
  from = module.osv_api.google_secret_manager_secret_iam_member.cloud_run_readonly_secret_access
  to   = google_secret_manager_secret_iam_member.legacy_compute_readonly_secret_access
}

