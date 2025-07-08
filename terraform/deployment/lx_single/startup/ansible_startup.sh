#!/bin/bash
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

echo "Installing Ansible on RedHat-based system..."
sudo yum install -y python3-pip
pip3 install ansible
pip3 install google-auth
declare -xr ANSIBLE_PROJECT_ID=${project_id}
declare -xr ANSIBLE_DEPLOYMENT_NAME=${deployment_name}
declare -xr ANSIBLE_INSTANCE_NAME=$(uname -n)

echo "Adding Ansible files to /tmp/"
sudo mkdir /tmp/group_vars
sudo mkdir /tmp/misc
sudo mkdir /tmp/callback_plugins

check_directory_use() {
    if mountpoint -q "$1"; then
        return 0  # Directory is in use
    else
        return 1  # Directory is not in use
    fi
}

if ${is_local_ssd}; then
    MOUNT_DIR="disk"
    COUNTER=0
    while [! check_directory_use "$${MOUNT_DIR}$${COUNTER}"]; do
        COUNTER=$((COUNTER + 1))
    done
    MOUNT_DIR="$${MOUNT_DIR}$${COUNTER}"
fi

echo "${playbook_content}" | base64 -d > /tmp/remote.yml
echo "${ha_content}" | base64 -d > /tmp/ha.yml
echo "${inventory_content}" | base64 -d > /tmp/inventory.yml
echo "${all_content}" | base64 -d > /tmp/group_vars/all.yml
echo "${gcp_ssh_wrapper}" | base64 -d > /tmp/misc/gcp-ssh-wrapper.sh
echo "${gcp_logging}" | base64 -d > /tmp/callback_plugins/gcp_logging.py
echo "${ansible_cfg}" | base64 -d > ansible.cfg
chmod +x /tmp/misc/gcp-ssh-wrapper.sh

echo "Running Ansible playbook..."
ansible-playbook -vvv /tmp/remote.yml -i /tmp/inventory.yml -e "node1_name=${node1_name}" -e "project_id=${project_id}" -e "zone1_name=${zone1_name}" -e "sql_secret_name=${sql_secret_name}" -e"mssql_edition=${sql_edition}" -e "mssql_version=${sql_version}" -e "is_local_ssd=${is_local_ssd}" -e "ssd_name=/mnt/disks/$${MOUNT_DIR}" -e "is_ha=${is_ha}"
