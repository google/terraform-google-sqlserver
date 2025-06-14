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

# This is a wrapper script allowing to use GCP's IAP SSH option to connect
# to our servers.

# Ansible passes a large number of SSH parameters along with the hostname as the
# second to last argument and the command as the last. We will pop the last two
# arguments off of the list and then pass all of the other SSH flags through
# without modification:
host="${@: -2: 1}"
cmd="${@: -1: 1}"

# Unfortunately ansible has hardcoded ssh options, so we need to filter these out
# It's an ugly hack, but for now we'll only accept the options starting with '--'
declare -a opts
for ssh_arg in "${@: 1: $# -3}" ; do
        if [[ "${ssh_arg}" == --* ]] ; then
                opts+="${ssh_arg} "
        fi
done

service_account=$(gcloud config list account --format "value(core.account)" | cut -d @ -f1)
gcloud compute ssh --internal-ip "service_account@$host" ${opts[*]} -- -C "${cmd}"