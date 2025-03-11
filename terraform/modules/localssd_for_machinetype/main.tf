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

variable "machine_type" {
  type = string
}

locals {
  machine_family = lower(split("-", var.machine_type)[0])
  cpu_count      = parseint(split("-", var.machine_type)[2], 10)

  # The number of scratch disks is based on the machine type.
  # https://cloud.google.com/compute/docs/disks/local-ssd#lssd_disk_options
  m3_scratch_disk_count = local.cpu_count <= 64 ? 4 : 8
  n2_scratch_disk_count = local.cpu_count < 10 ? 1 : (
    local.cpu_count < 20 ? 2 : (
      local.cpu_count < 40 ? 4 : (
        local.cpu_count < 80 ? 8 : 16
      )
    )
  )
  scratch_disk_count = local.machine_family == "m3" ? local.m3_scratch_disk_count : ((local.machine_family == "n2" || local.machine_family == "n2d") ? local.n2_scratch_disk_count : 0)
}

output "count" {
  value = local.scratch_disk_count
}
