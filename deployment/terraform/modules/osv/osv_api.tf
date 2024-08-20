# The OSV API on Cloud Run
# Adapted from https://github.com/hashicorp/terraform-provider-google/issues/5528#issuecomment-1136040976

resource "google_cloud_run_service" "api_backend" {
  project  = var.project_id
  name     = "osv-grpc-backend"
  location = "us-central1"

  template {
    spec {
      containers {
        image = "us-docker.pkg.dev/cloudrun/container/hello:latest" # Placeholder image.
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  lifecycle {
    ignore_changes = [
      # To be managed by Cloud Deploy.
      template,
      traffic,
    ]
    prevent_destroy = true
  }
}

resource "google_cloud_run_v2_service" "api_backend_batch" {
  project  = var.project_id
  name     = "osv-grpc-backend-batch"
  location = "us-central1"

  template {
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello:latest" # Placeholder image.
    }
  }

  lifecycle {
    ignore_changes = [
      # To be managed by Cloud Deploy.
      template,
      traffic,
      labels,
      client
    ]
    prevent_destroy = true
  }
}

variable "_api_descriptor_file" {
  # This isn't actually sensitive, but it's outputted as a massive base64 string which really floods the plan output.
  sensitive = true
  type      = string
  default   = "api/api_descriptor.pb"
}

resource "google_endpoints_service" "grpc_service" {
  project      = var.project_id
  service_name = var.api_url
  grpc_config = templatefile(
    "api/api_config.tftpl",
    {
      service_name      = var.api_url,
      backend_url       = replace(google_cloud_run_service.api_backend.status[0].url, "https://", "grpcs://")
      backend_batch_url = replace(google_cloud_run_v2_service.api_backend_batch.uri, "https://", "grpcs://")
  })
  protoc_output_base64 = filebase64(var._api_descriptor_file)
}

resource "google_project_service" "grpc_service_api" {
  project = var.project_id
  service = google_endpoints_service.grpc_service.service_name
}


data "external" "esp_version" {
  program = ["bash", "${path.module}/scripts/esp_full_version", "${var.esp_version}"]
}

resource "null_resource" "grpc_proxy_image" {
  triggers = {
    # Update this when the config changes or there is a new ESP image
    config_id   = google_endpoints_service.grpc_service.config_id
    esp_version = data.external.esp_version.result.esp_full_version
  }

  # Script obtained from:
  # https://github.com/GoogleCloudPlatform/esp-v2/blob/master/docker/serverless/gcloud_build_image
  provisioner "local-exec" {
    command = <<EOS
      bash ${path.module}/scripts/gcloud_build_image \
        -s ${var.api_url} \
        -c ${google_endpoints_service.grpc_service.config_id} \
        -p ${var.project_id} \
        -v ${var.esp_version}
    EOS
  }
}

data "google_container_registry_image" "api" {
  project = var.project_id
  name    = "endpoints-runtime-serverless"
  tag = format(
    "%s-%s-%s",
    data.external.esp_version.result.esp_full_version,
    var.api_url,
    google_endpoints_service.grpc_service.config_id
  )
  depends_on = [null_resource.grpc_proxy_image]
}


resource "google_cloud_run_service" "api" {
  project  = var.project_id
  name     = "osv-grpc-v1"
  location = "us-central1"

  template {
    spec {
      containers {
        image = data.google_container_registry_image.api.image_url
        env {
          name  = "ESPv2_ARGS"
          value = "^++^--transcoding_preserve_proto_field_names++--envoy_connection_buffer_limit_bytes=104857600"
        }
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  autogenerate_revision_name = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_cloud_run_domain_mapping" "api" {
  project  = var.project_id
  name     = var.api_url
  location = google_cloud_run_service.api.location
  metadata {
    namespace = var.project_id
  }
  spec {
    route_name = google_cloud_run_service.api.name
  }
}
