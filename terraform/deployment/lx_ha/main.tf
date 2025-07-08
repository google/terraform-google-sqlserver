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

module "lx_ha" {
  source                          = "../../modules/sql_lx"
  deployment_name                 = var.deployment_name
  sql_boot_disk_image_os          = var.sql_boot_disk_image_os
  is_sql_payg                     = var.is_sql_payg
  sql_server_edition              = var.sql_server_edition
  sql_server_version              = var.sql_server_version
  deployment_model                = var.deployment_model
  vm_prefix                       = var.vm_prefix
  media_bucket_name               = var.media_bucket_name
  gcp_project_id                  = var.gcp_project_id
  region_name                     = var.region_name
  zone1_name                      = var.zone1_name
  zone2_name                      = var.zone2_name
  zone3_name                      = var.zone3_name
  vpc_name                        = var.vpc_name
  subnet_name                     = var.subnet_name
  public_ip                       = var.public_ip
  scopes                          = var.scopes
  sql_server_secret_name          = var.sql_server_secret_name
  is_sole_tenant                  = var.is_sole_tenant
  sole_tenant_node_affinity_key   = var.sole_tenant_node_affinity_key
  sole_tenant_node_affinity_value = var.sole_tenant_node_affinity_value
  machine_type                    = var.machine_type
  disk_type                       = var.disk_type
  is_smt_off                      = var.is_smt_off
  is_temp_db_on_local_ssd         = var.is_temp_db_on_local_ssd
  node_count                      = 3
}