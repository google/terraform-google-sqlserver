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

variable "high_availability_type" {
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

variable "zone1_name" {
  type        = string
  description = "Zone where the instances will be created."
}

variable "zone2_name" {
  type        = string
  description = "Secondary zone where the instances will be created."
}

variable "zone3_name" {
  type        = string
  default     = null
  description = "Third zone where the instances will be created."
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
    "https://www.googleapis.com/auth/trace.append",
  "https://www.googleapis.com/auth/cloud-platform"]
}

variable "sql_server_secret_name" {
  type = string
}

variable "is_sole_tenant" {
  type = string
}

variable "sole_tenant_node_affinity_key" {
  default = "compute.googleapis.com/node-name"
  type    = string
}

variable "sole_tenant_node_affinity_value" {
  default = "node1-name"
  type    = string
}

variable "sole_tenant_node2_affinity_key" {
  default = "compute.googleapis.com/node-name"
  type    = string
}

variable "sole_tenant_node2_affinity_value" {
  default = "node2-name"
  type    = string
}

variable "machine_type" {
  type = string
}

variable "disk_type" {
  default = "pd-ssd"
}

variable "is_smt_off" {
  default = false
  type    = bool
}

variable "is_temp_db_on_local_ssd" {
  default = true
  type    = bool
}

variable "deployment_timeout_1" {
  description = "Timeout in seconds for monitoring the configuration process after each Windows startup."
  type        = number
  default     = 3600
}

variable "deployment_timeout_2" {
  description = "Overall timeout in seconds for the entire configuration process, spanning multiple reboots. This timeout ensures that the complete configuration, including all reboots and configuration steps, finishes within the allocated time."
  type        = number
  default     = 10800
}
