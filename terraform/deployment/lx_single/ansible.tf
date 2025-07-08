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

resource "google_compute_disk" "sqldansible11" {
  name    = "${var.vm_prefix}-ansible-disk"
  project = var.gcp_project_id
  size    = 50
  type    = "pd-ssd"
  zone    = var.zone1_name
  image   = "projects/rhel-cloud/global/images/rhel-9-v20230615"
  lifecycle {
    ignore_changes = [snapshot, image]
  }
  timeouts {
    create = "1h"
    delete = "1h"
    update = "1h"
  }
}

data "local_file" "remote_playbook" {
  filename = "../../../ansible/remote.yml"
}

data "local_file" "remote_ha" {
  filename = "../../../ansible/ha.yml"
}

data "local_file" "inventory" {
  filename = "../../../ansible/inventory_single.yml"
}

data "local_file" "all_content" {
  filename = "../../../ansible/group_vars/all.yml"
}

data "local_file" "gcp_ssh_wrapper" {
  filename = "../../../ansible/misc/gcp-ssh-wrapper.sh"
}

data "local_file" "ansible_cfg" {
  filename = "../../../ansible/ansible.cfg"
}

data "local_file" "gcp_logging" {
  filename = "../../../ansible/callback_plugins/gcp_logging.py"
}

resource "google_compute_instance" "sqlansible11" {
  project      = var.gcp_project_id
  zone         = var.zone1_name
  name         = "${var.vm_prefix}-ansible-runner"
  machine_type = "n1-standard-16"

  depends_on = [module.lx-single]

  boot_disk {
    device_name = "persistent-disk-0"
    source      = google_compute_disk.sqldansible11.self_link
  }

  network_interface {
    network    = var.vpc_name
    subnetwork = var.subnet_name
    access_config {}
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

  service_account {
    scopes = var.scopes
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    startup-script = templatefile("${path.module}/startup/ansible_startup.sh",
      {
        playbook_content  = base64encode(data.local_file.remote_playbook.content),
        ha_content        = base64encode(data.local_file.remote_ha.content),
        inventory_content = base64encode(data.local_file.inventory.content),
        all_content       = base64encode(data.local_file.all_content.content),
        gcp_ssh_wrapper   = base64encode(data.local_file.gcp_ssh_wrapper.content),
        ansible_cfg       = base64encode(data.local_file.ansible_cfg.content),
        gcp_logging       = base64encode(data.local_file.gcp_logging.content),
        sql_version       = var.sql_server_version,
        sql_edition       = var.sql_server_edition,
        is_local_ssd      = var.is_temp_db_on_local_ssd,
        project_id        = var.gcp_project_id,
        sql_secret_name   = var.sql_server_secret_name,
        deployment_name   = var.deployment_name
        node1_name        = "${var.vm_prefix}-0"
        zone1_name        = var.zone1_name
        is_ha             = var.deployment_model == "HA" ? true : false
      }
    )
    enable-oslogin = "FALSE"
  }
}