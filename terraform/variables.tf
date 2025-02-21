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

// Deployment Basics
variable "deployment_name" {
  description = "deployment_name"
}

variable "operating_system" {
  default     = "Windows"
  description = "operating_system"
}

variable "is_sql_payg" {
  description = "is_sql_payg"
}

variable "deployment_model" {
  default     = "HA"
  description = "deployment_model"
}

variable "high_availability_type" {
  default     = "AG"
  description = "high_availability_type"
}

variable "fci_type" {
  default     = "s2d"
  description = "fci_type"
}

variable "sql_boot_disk_image_os" {
  description = "sql_boot_disk_image_os"
}

variable "sql_server_edition" {
  description = "sql_server_edition"
}

variable "sql_server_version" {
  description = "sql_server_version"
}

variable "vm_prefix" {
  default     = "sql"
  description = "vm_prefix"
}

variable "media_bucket_name" {
  description = "media_bucket_name"
}

// Location & Networking
variable "gcp_project_id" {
  description = "gcp_project_id"
}

variable "region_name" {
  description = "region_name"
}

variable "zone1_name" {
  description = "zone1_name"
}

variable "zone2_name" {
  description = "zone2_name"
}

variable "vpc_name" {
  default     = "default"
  description = "vpc_name"
}

variable "subnet_name" {
  default     = "default"
  description = "subnet_name"
}

variable "existing_dns_zone_name" {
  default     = ""
  description = "existing_dns_zone_name"
}

// Active Directory
variable "active_directory_domain_username" {
  description = "active_directory_domain_username"
}

variable "active_directory_secret_name" {
  description = "active_directory_secret_name"
}

variable "active_directory_dns_name" {
  description = "active_directory_dns_name"
}

variable "active_directory_ou" {
  description = "active_directory_ou"
}

// Database
variable "sql_server_secret_name" {
  description = "sql_server_secret_name"
}

variable "sql_server_floating_ip" {
  description = "sql_server_floating_ip"
}

variable "is_sole_tenant" {
  default     = false
  description = "tenancy_model"
}

variable "sole_tenant_node_affinity_key" {
  description = "sole_tenant_node_affinity_key"
}

variable "sole_tenant_node_affinity_value" {
  description = "sole_tenant_node_affinity_value"
}

variable "machine_type" {
  default     = "n1-highem-32"
  description = "machine_type"
}

variable "disk_type" {
  default     = "pd-ssd"
  description = "disk_type"
}

variable "is_smt_off" {
  default     = false
  description = "is_smt_off"
}

variable "is_temp_db_on_local_ssd" {
  default     = true
  description = "is_temp_db_on_local_ssd"
}

// Pacemaker
variable "pacemaker_cluster_name" {
  description = "pacemaker_cluster_name"
}

variable "pacemaker_cluster_username" {
  description = "pacemaker_cluster_username"
}

variable "pacemaker_cluster_secret_name" {
  default     = "default"
  description = "pacemaker_cluster_secret_name"
}

variable "sql_pacemaker_username" {
  default     = "hacluster"
  description = "sql_pacemaker_username"
}

variable "sql_pacemaker_secret_name" {
  default     = "default"
  description = "sql_pacemaker_secret_name"
}

variable "bucket_name_node_certificates" {
  description = "bucket_name_node_certificates"
}
