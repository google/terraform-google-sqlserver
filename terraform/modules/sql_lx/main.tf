# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

locals {
  vm_image     = var.sql_boot_disk_image_os
  vm_prefix    = var.vm_prefix
  iso_bucket   = var.media_bucket_name
  project_id   = var.gcp_project_id
  region       = var.region_name
  zones        = [var.zone1_name, var.zone2_name, var.zone3_name]
  network      = var.vpc_name
  subnetwork   = var.subnet_name
  machine_type = var.machine_type
  disk_type    = var.disk_type
  scopes       = var.scopes
  node_count   = var.node_count
  sql_edition  = lower(var.sql_server_edition)
}

data "local_file" "crm_config" {
  filename = "${path.module}/crm_config.sh"
}

data "google_secret_manager_secret_version_access" "sql_secret" {
  project = local.project_id
  secret  = var.sql_server_secret_name
}

resource "google_compute_disk" "disk_with_license" {
  count    = local.node_count
  project  = local.project_id
  zone     = local.zones[count.index]
  name     = "${local.vm_prefix}-disk-${count.index}"
  size     = 100
  type     = local.disk_type
  image    = local.vm_image
  licenses = var.is_sql_payg ? ["https://www.googleapis.com/compute/v1/projects/linux-sql-cloud/global/licenses/sql-server-${var.sql_server_version}-${local.sql_edition}-on-linux"] : []
}

resource "google_compute_disk" "data_disk" {
  count   = local.node_count
  project = local.project_id
  zone    = local.zones[count.index]
  name    = "${local.vm_prefix}-data-${count.index}"
  type    = local.disk_type
  size    = 500
}

module "localssd_for_machinetype" {
  source       = "../localssd_for_machinetype"
  machine_type = var.machine_type
}

resource "google_compute_instance" "sql_lx" {
  count        = local.node_count
  project      = local.project_id
  zone         = local.zones[count.index]
  name         = "${local.vm_prefix}-${count.index}"
  machine_type = local.machine_type
  tags         = ["linaoagtag"]

  boot_disk {
    source = google_compute_disk.disk_with_license[count.index].self_link
  }

  attached_disk {
    source = google_compute_disk.data_disk[count.index].self_link
  }

  dynamic "scratch_disk" {
    for_each = var.is_temp_db_on_local_ssd ? range(module.localssd_for_machinetype.count) : []
    content {
      interface = "NVME"
    }
  }

  network_interface {
    network    = local.network
    subnetwork = local.subnetwork
    # Empty access config results in an ephemeral, public IP address.
    # We only include access_config if public_ip is true.
    dynamic "access_config" {
      for_each = var.public_ip ? [1] : []
      content {
      }
    }
  }

  dynamic "scheduling" {
    for_each = var.is_sole_tenant ? [0] : []
    content {
      node_affinities {
        key      = var.sole_tenant_node_affinity_key
        operator = "IN"
        values   = tolist([var.sole_tenant_node_affinity_value])
      }
    }
  }

  advanced_machine_features {
    threads_per_core = var.is_smt_off ? 2 : 1
  }

  service_account {
    scopes = local.scopes
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    type = "sql"
    startup-script = templatefile("${path.module}/sql-lx.sh", {
      crm_content     = base64encode(data.local_file.crm_config.content),
      sa_password     = "${data.google_secret_manager_secret_version_access.sql_secret.secret_data}"
      sql_version     = var.sql_server_version,
      sql_edition     = local.sql_edition,
      is_local_ssd    = var.is_temp_db_on_local_ssd,
      project_id      = local.project_id,
      deployment_name = var.deployment_name
      is_ha           = var.deployment_model == "HA" ? true : false
    })
    enable-oslogin = "FALSE"
  }

  allow_stopping_for_update = true
}

output "sql_lx_node0" {
  value = google_compute_instance.sql_lx[0].self_link
}

output "sql_lx_node1" {
  value = var.deployment_model == "HA" ? google_compute_instance.sql_lx[1].self_link : null
}

output "sql_lx_node2" {
  value = var.deployment_model == "HA" ? google_compute_instance.sql_lx[2].self_link : null
}


resource "google_compute_instance_group" "lxha_instance_group" {
  count       = local.node_count
  project     = local.project_id
  zone        = local.zones[count.index]
  name        = "${local.vm_prefix}-${count.index}-uig"
  description = "Unmanaged instance group for ${local.vm_prefix}-${count.index}"
  instances = [
    "projects/${local.project_id}/zones/${local.zones[count.index]}/instances/${local.vm_prefix}-${count.index}"
  ]
  depends_on = [google_compute_instance.sql_lx]
}

resource "google_compute_firewall" "health_check_fw_60011" {
  count   = var.deployment_model == "HA" ? 1 : 0
  name    = "${local.vm_prefix}-healthcheck-fw"
  network = var.vpc_name
  project = local.project_id

  allow {
    protocol = "tcp"
    ports    = ["60011"]
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  priority      = 998
  target_tags   = ["linaoagtag"]
}

resource "google_compute_region_backend_service" "lxha_lb_backend_service" {
  count                 = var.deployment_model == "HA" ? 1 : 0
  name                  = "${local.vm_prefix}-backend-service"
  load_balancing_scheme = "INTERNAL"
  protocol              = "TCP"
  region                = local.region
  project               = var.gcp_project_id
  health_checks         = [google_compute_health_check.aoag1_health_check[0].self_link]

  dynamic "backend" {
    for_each = google_compute_instance_group.lxha_instance_group
    content {
      group          = backend.value.id
      balancing_mode = "CONNECTION"
    }
  }
  depends_on = [google_compute_instance_group.lxha_instance_group]
}

output "lxha_lb_backend_service" {
  value = var.deployment_model == "HA" ? google_compute_region_backend_service.lxha_lb_backend_service[0].self_link : null
}

resource "google_compute_health_check" "aoag1_health_check" {
  count   = var.deployment_model == "HA" ? 1 : 0
  name    = "${local.vm_prefix}-health-check"
  project = var.gcp_project_id

  timeout_sec         = 10
  check_interval_sec  = 10
  unhealthy_threshold = 2
  healthy_threshold   = 2

  log_config {
    enable = true
  }

  tcp_health_check {
    port = "60011"
  }
}