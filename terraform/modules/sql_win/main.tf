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

provider "google" {
  project         = local.project_id
  request_timeout = "30m"
}

data "google_project" "project" {
  project_id = var.gcp_project_id
}

locals {
  vm_image                         = var.sql_boot_disk_image_os
  vm_prefix                        = var.vm_prefix
  iso_bucket                       = var.media_bucket_name
  project_id                       = var.gcp_project_id
  region                           = var.region_name
  zones                            = var.zones
  network                          = var.vpc_name
  subnetwork                       = var.subnet_name
  domain_ip                        = var.active_directory_ip
  active_directory_domain_username = var.active_directory_domain_username
  domain_name                      = var.active_directory_dns_name
  machine_type                     = var.machine_type
  disk_type_map = {
    "n2" = "pd-ssd"
    "e2" = "pd-ssd"
    "m3" = "hyperdisk-balanced"
    "c3" = "hyperdisk-balanced"
    "c4" = "hyperdisk-balanced"
    "n4" = "hyperdisk-balanced"
  }
  disk_type                = var.disk_type == "" ? local.disk_type_map[lower(substr(local.machine_type, 0, 2))] : var.disk_type
  windows_image            = var.sql_boot_disk_image_os
  scopes                   = var.scopes
  node_count               = var.node_count
  capacity_data_disk_count = var.capacity_data_disk_count
  capacity_log_disk_count  = var.capacity_log_disk_count
  mask                     = var.mask
  sa_strings               = split("/", var.sa_name)
  sa_name                  = length(local.sa_strings) > 0 ? element(local.sa_strings, length(local.sa_strings) - 1) : ""
  qwiklab_label_key        = "workloadmanager-sql-tf-qwiklab"
  project_labels           = data.google_project.project.labels
  is_qwiklab_project       = local.project_labels != null && contains(keys(local.project_labels), local.qwiklab_label_key)
}

module "sysprep" {
  source = "../sysprep"
}

module "localssd_for_machinetype" {
  source       = "../localssd_for_machinetype"
  machine_type = var.machine_type
}

module "win_startup" {
  source = "../win_startup"
}

resource "google_compute_disk" "data_disk" {
  count   = local.node_count * local.capacity_data_disk_count
  name    = "${local.vm_prefix}-data-${count.index}"
  project = local.project_id
  zone    = local.zones[floor(count.index / local.capacity_data_disk_count)]
  type    = local.disk_type
  size    = local.is_qwiklab_project ? local.project_labels[local.qwiklab_label_key] : 500
}

resource "google_compute_disk" "log_disk" {
  count   = local.node_count * local.capacity_log_disk_count
  name    = "${local.vm_prefix}-log-${count.index}"
  project = local.project_id
  zone    = local.zones[floor(count.index / local.capacity_log_disk_count)]
  type    = local.disk_type
  size    = local.is_qwiklab_project ? local.project_labels[local.qwiklab_label_key] : 500
}

resource "google_compute_instance" "sql_win" {
  provider     = google
  count        = local.node_count
  project      = local.project_id
  zone         = local.zones[count.index]
  name         = "${local.vm_prefix}-${count.index}"
  machine_type = local.machine_type

  lifecycle {
    ignore_changes = [
      metadata["sysprep-specialize-script-ps1"]
    ]
  }

  boot_disk {
    initialize_params {
      image = local.vm_image
      type  = local.disk_type
      size  = 100
    }
  }

  dynamic attached_disk {
    for_each = range(local.capacity_data_disk_count)
    content {
      source = google_compute_disk.data_disk[count.index * local.capacity_data_disk_count + attached_disk.key].self_link
    }
  }

  dynamic attached_disk {
    for_each = range(local.capacity_log_disk_count)
    content {
      source = google_compute_disk.log_disk[count.index * local.capacity_log_disk_count + attached_disk.key].self_link
    }
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
        key      = var.sole_tenant_node_affinity_key[count.index]
        operator = "IN"
        values   = [var.sole_tenant_node_affinity_value[count.index]]
      }
    }
  }

  advanced_machine_features {
    threads_per_core = var.is_smt_off ? 2 : 1
  }

  service_account {
    email  = local.sa_name
    scopes = local.scopes
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    type = "sql"
    windows-startup-script-ps1 = templatefile(module.win_startup.path_configure_local_ssd, {
      isLocalSsd         = var.is_temp_db_on_local_ssd,
      deploymentName     = var.deployment_name,
      deploymentTimeout1 = var.deployment_timeout_1,
      deploymentTimeout2 = var.deployment_timeout_2,
      nameHost           = "${local.vm_prefix}-${count.index}",
      zone               = local.zones[count.index],
      isFirst            = (count.index == 0) && var.sysprep_file == "dsc_configuration.ps1",
    })
    sysprep-specialize-script-ps1 = templatefile(module.sysprep.path_specialize, {
      nameHost      = "${local.vm_prefix}-${count.index}",
      adSecretName  = var.active_directory_secret_name,
      sqlSecretName = var.sql_server_secret_name,
      parametersConfiguration = jsonencode({
        projectId           = local.project_id,
        deploymentName      = var.deployment_name,
        vmImage             = local.vm_image,
        isoBucket           = local.iso_bucket,
        domainName          = local.domain_name,
        domainIp            = local.domain_ip,
        adUsername          = local.active_directory_domain_username,
        vmPrefix            = local.vm_prefix,
        isFirst             = (count.index == 0),
        sqlFciIp            = var.sql_fci_ip,
        isLocalSsd          = var.is_temp_db_on_local_ssd,
        inlineMeta          = filebase64(module.sysprep.path_meta),
        inlineConfiguration = filebase64("${path.module}/${var.sysprep_file}"),
        mask                = var.mask
        modulesDsc = [
          {
            Name    = "FailoverClusterDsc",
            Version = "2.1.0"
          },
          {
            Name    = "SqlServerDsc",
            Version = "15.1.1"
          }
        ]
      })
    })
  }

  allow_stopping_for_update = true
}