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

resource "google_compute_address" "sql_fci_ip" {
  count        = var.high_availability_type == "AG" ? 0 : 1
  region       = var.region_name
  project      = var.gcp_project_id
  name         = "${var.vm_prefix}-fci-ip"
  address_type = "INTERNAL"
  subnetwork   = var.subnet_name
}

module "win_cluster" {
  source                           = "../../modules/sql_win"
  deployment_name                  = var.deployment_name
  sql_boot_disk_image_os           = var.sql_boot_disk_image_os
  vm_prefix                        = var.vm_prefix
  media_bucket_name                = var.media_bucket_name
  gcp_project_id                   = var.gcp_project_id
  region_name                      = var.region_name
  zones                            = [var.zone1_name, var.zone2_name]
  vpc_name                         = var.vpc_name
  subnet_name                      = var.subnet_name
  public_ip                        = var.public_ip
  active_directory_ip              = var.active_directory_ip
  active_directory_domain_username = var.active_directory_domain_username
  active_directory_secret_name     = var.active_directory_secret_name
  active_directory_dns_name        = var.active_directory_dns_name
  sa_name                          = var.sa_name
  scopes                           = var.scopes
  sql_server_secret_name           = var.sql_server_secret_name
  is_sole_tenant                   = var.is_sole_tenant
  sole_tenant_node_affinity_key    = [var.sole_tenant_node_affinity_key, var.sole_tenant_node2_affinity_key]
  sole_tenant_node_affinity_value  = [var.sole_tenant_node_affinity_value, var.sole_tenant_node2_affinity_value]
  machine_type                     = var.machine_type
  disk_type                        = var.disk_type
  is_smt_off                       = var.is_smt_off
  is_temp_db_on_local_ssd          = (var.high_availability_type == "FCI" || var.is_sole_tenant) ? false : var.is_temp_db_on_local_ssd
  node_count                       = 2
  capacity_data_disk_count         = var.high_availability_type == "AG" ? 1 : 4
  capacity_log_disk_count          = var.high_availability_type == "AG" ? 1 : 0
  sql_fci_ip                       = var.high_availability_type == "AG" ? "" : google_compute_address.sql_fci_ip[0].address
  sysprep_file                     = "dsc_configuration.ps1"
  mask                             = var.high_availability_type == "AG" ? 2 : 4
  deployment_timeout_1             = var.deployment_timeout_1
  deployment_timeout_2             = var.deployment_timeout_2
}

module "witness" {
  source                           = "../../modules/sql_win"
  deployment_name                  = var.deployment_name
  sql_boot_disk_image_os           = var.sql_boot_disk_image_os
  vm_prefix                        = "${var.vm_prefix}-w"
  media_bucket_name                = var.media_bucket_name
  gcp_project_id                   = var.gcp_project_id
  region_name                      = var.region_name
  zones                            = [var.zone3_name]
  vpc_name                         = var.vpc_name
  subnet_name                      = var.subnet_name
  public_ip                        = var.public_ip
  active_directory_ip              = var.active_directory_ip
  active_directory_domain_username = var.active_directory_domain_username
  active_directory_secret_name     = var.active_directory_secret_name
  active_directory_dns_name        = var.active_directory_dns_name
  sa_name                          = var.sa_name
  scopes                           = var.scopes
  sql_server_secret_name           = var.sql_server_secret_name
  is_sole_tenant                   = false
  machine_type                     = var.machine_type
  disk_type                        = var.disk_type
  is_smt_off                       = var.is_smt_off
  is_temp_db_on_local_ssd          = var.is_sole_tenant ? false : var.is_temp_db_on_local_ssd
  node_count                       = 1
  sysprep_file                     = "witness_aoag.ps1"
  mask                             = 0
  deployment_timeout_1             = var.deployment_timeout_1
  deployment_timeout_2             = var.deployment_timeout_2
  capacity_data_disk_count         = 0
  capacity_log_disk_count          = 0
}