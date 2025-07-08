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

install_pymssql() {
    echo Installing pymssql
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release  # Source the os-release file for variables
        case "$ID" in
            debian|ubuntu)
                echo "Installing pymssql on Debian-based system..."
                sudo apt-get update
                sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pymssql
                ;;
            centos|rhel|fedora)
                echo "Installing pymssql on RedHat-based system..."
                sudo dnf install -y python3-pip
                # pymssql 2.3 requires Python >= 3.7
                sudo python3 -m pip install -U pip
                export PYMSSQL_BUILD_WITH_BUNDLED_FREETDS=1
                sudo python3 -m pip install pymssql==2.3.0
                ;;
            sles|opensuse*)
                echo "Installing pymssql on SUSE-based system..."
                sudo zypper install -y python3-pip
                sudo pip3 install pymssql==2.3.0
                ;;
            *)
                echo "Unsupported distribution. Exiting..."
                exit 1
                ;;
        esac
    else
        echo "Unable to detect distribution. Exiting..."
        exit 1
    fi
}

check_directory_use() {
    if mountpoint -q "$1"; then
        return 0  # Directory is in use
    else
        return 1  # Directory is not in use
    fi
}

# Format and mount the data disk
if [[ -e /dev/sdb ]]; then
    echo "Starting to mount the data disk to /mnt/disks/mssql"
    # Format the disk
    sudo mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/sdb
    # Create the mount directory
    sudo mkdir -p /mnt/disks/mssql
    # Mount the disk
    sudo mount -o discard,defaults /dev/sdb /mnt/disks/mssql
    sudo chmod a+w /mnt/disks/mssql
    # Add an entry to /etc/fstab to persist the mount
    echo UUID=$(sudo blkid -s UUID -o value /dev/sdb) /mnt/disks/mssql ext4 discard,defaults,nofail 0 2 | sudo tee -a /etc/fstab
    echo "Finished mounting the data disk to /mnt/disks/mssql"
    sudo mkdir -p /mnt/disks/mssql/data
    sudo chmod a+w /mnt/disks/mssql/data
fi

if ${is_local_ssd}; then
    MOUNT_DIR="disk" 
    COUNTER=0
    while [! check_directory_use "$${MOUNT_DIR}$${COUNTER}"]; do
        COUNTER=$((COUNTER + 1))
    done
    MOUNT_DIR="$${MOUNT_DIR}$${COUNTER}"

    # Identify the Local SSD
    SSD_NAME=$(sudo find /dev/ | grep google-local-nvme-ssd)
    sudo mkfs.ext4 -F $${SSD_NAME}
    sudo mkdir -p /mnt/disks/$${MOUNT_DIR}
    echo "Using /mnt/disks/$${MOUNT_DIR} as the mount directory for $${SSD_NAME}"
    # Mount the Local SSD to the VM
    sudo mount $${SSD_NAME} /mnt/disks/$${MOUNT_DIR}
    sudo chmod a+w /mnt/disks/$${MOUNT_DIR}
    echo "Finished mounting the local ssd"
    # Add an entry to /etc/fstab to persist the mount
    echo UUID=$(sudo blkid -s UUID -o value $${SSD_NAME}) /mnt/disks/$${MOUNT_DIR} ext4 discard,defaults,nofail 0 2 | sudo tee -a /etc/fstab
fi

install_pymssql

mkdir -p /tmp/callback_plugins
echo "${crm_content}" | base64 -d > /tmp/crm_config.sh