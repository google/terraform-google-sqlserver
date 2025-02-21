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

variable "deployment_name" {
  type = string
}

variable "sql_boot_disk_image_os" {
  type = string
}

variable "vm_prefix" {
  type = string
}

variable "media_bucket_name" {
  type = string
}

variable "gcp_project_id" {
  type        = string
  description = "Project id where the instances will be created."
}

variable "region_name" {
  type        = string
  description = "Region where the instances will be created."
}

variable "zones" {
  type        = list
  description = "Zones where the instances will be created."
}

variable "vpc_name" {
  type = string
}

variable "subnet_name" {
  type = string
}

variable "public_ip" {
  type = bool
}

variable "active_directory_ip" {
  type = string
}

variable "active_directory_domain_username" {
  type = string
}

variable "active_directory_secret_name" {
  type = string
}

variable "active_directory_dns_name" {
  type = string
}

variable "sa_name" {
  default = ""
  type    = string
}

variable "scopes" {
  default = ["https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/logging.write",
    "https://www.googleapis.com/auth/monitoring.write",
    "https://www.googleapis.com/auth/service.management.readonly",
    "https://www.googleapis.com/auth/servicecontrol",
  "https://www.googleapis.com/auth/trace.append"]
}

variable "sql_server_secret_name" {
  type = string
}

variable "is_sole_tenant" {
  type = string
}

variable "sole_tenant_node_affinity_key" {
  default = []
  type    = list
}

variable "sole_tenant_node_affinity_value" {
  default = []
  type    = list
}

variable "machine_type" {
  type = string
}

variable "disk_type" {
  type = string
}

variable "is_smt_off" {
  default = false
  type    = bool
}

variable "is_temp_db_on_local_ssd" {
  default = true
  type    = bool
}

variable "node_count" {
  default = 1
  type    = number
}

variable "sysprep_file" {
  type = string
}

variable "capacity_data_disk_count" {
  type    = number
  default = 1
}

variable "capacity_log_disk_count" {
  type    = number
  default = 1
}

variable "sql_fci_ip" {
  type    = string
  default = ""
}

variable "mask" {
  type = number
}

variable "deployment_timeout_1" {
  type = number
}

variable "deployment_timeout_2" {
  type = number
}