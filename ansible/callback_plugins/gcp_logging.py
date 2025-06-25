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

import datetime
import logging
import os
from typing import Any

from ansible.plugins import callback
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import GcpSession


class CallbackModule(callback.CallbackBase):
  """Ansible callback plugin to get execution data and send it to cloud logging."""

  CALLBACK_NAME = 'gcp_logging'

  def __init__(self, options=None):
    super(CallbackModule, self).__init__()

  def send_gcp_log(self, log_data: Any) -> None:
    """Send log to GCP project."""

    project = os.environ.get('ANSIBLE_PROJECT_ID')
    log_name = 'Ansible_logs'

    self.params = {
        'auth_kind': 'application',
        'scopes': 'https://www.googleapis.com/auth/logging.write',
    }
    auth = GcpSession(self, 'logging')
    response = auth.post(
        'https://logging.googleapis.com/v2/entries:write',
        {
            'entries': [
                {
                    'logName': f'projects/{project}/logs/{log_name}',
                    'resource': {
                        'type': 'global',
                        'labels': {
                            'project_id': project,
                        },
                    },
                    'jsonPayload': log_data,
                },
            ],
        },
    )

    if response.status_code != 200:
      print(
          'Logs could not be sent: {} {}'.format(
              response.status_code, response.json()['error']['message']
          )
      )

  def send_task_result(self, task_status: str, result: Any) -> None:

    task_name = str(result._task).replace('TASK: ', '').replace('HANDLER: ', '')
    host_name = os.environ.get('ANSIBLE_INSTANCE_NAME')

    task_info = {
        'timestamp': str(datetime.datetime.now()),
        'state': task_status,
        'step_name': task_name,
        'instance_name': host_name,
        'deployment_name': os.environ.get('ANSIBLE_DEPLOYMENT_NAME'),
        'path': result._task.get_path(),
    }

    if task_status == 'failed':
      task_info['error_message'] = result._result.get('stderr', 'None')
      task_info['results'] = result._result

    if task_status == 'ignored_errors':
      task_info['results'] = result._result

    self.send_gcp_log(task_info)

  def v2_playbook_on_start(self, playbook: Any, *args, **kwargs) -> None:
    """See base class."""

    playbook_info = {
        'timestamp': str(datetime.datetime.now()),
        'state': 'playbook_start',
        'deployment_name': os.environ.get('ANSIBLE_DEPLOYMENT_NAME'),
        'file_name': playbook._file_name.rpartition('/')[2],
        'base_dir': playbook._basedir,
    }

    self.send_gcp_log(playbook_info)

  def v2_playbook_on_play_start(self, play: Any) -> None:
    """See base class."""
    vm = play.get_variable_manager()
    variables = vm.get_vars(play=play)
    all_hosts = variables['vars']['ansible_play_hosts_all']

    all_tasks = play.get_tasks()[0]
    all_task_names = [
        task.get_name() for task in all_tasks if hasattr(task, 'get_name')
    ]

    play_info = {
        'timestamp': str(datetime.datetime.now()),
        'state': 'play_start',
        'deployment_name': os.environ.get('ANSIBLE_DEPLOYMENT_NAME'),
        'play_name': play.get_name().strip(),
        'all_task_names': all_task_names,
        'all_instances': all_hosts,
    }

    self.send_gcp_log(play_info)

  def playbook_on_task_start(self, name: str, is_conditional: bool) -> None:
    task_info = {
        'timestamp': str(datetime.datetime.now()),
        'state': 'task_start',
        'deployment_name': os.environ.get('ANSIBLE_DEPLOYMENT_NAME'),
        'step_name': name,
    }

    self.send_gcp_log(task_info)

  def v2_runner_on_ok(self, result: Any, **kwargs) -> None:
    self.send_task_result('success', result)

  def v2_runner_on_failed(self, result: Any, ignore_errors: Any = ...) -> None:
    if ignore_errors:
      self.send_task_result('ignored_errors', result)
      return
    self.send_task_result('failed', result)

  def v2_runner_on_unreachable(self, result: Any, **kwargs) -> None:
    self.send_task_result('failed', result)

  def v2_runner_on_skipped(self, result: Any, **kwargs) -> None:
    self.send_task_result('skipped', result)

  def v2_playbook_on_stats(self, stats: Any) -> None:
    """See base class."""
    try:
      playbook_stats = {
          'processed': stats.processed,
          'failures': stats.failures,
          'ok': stats.ok,
          'unreachable': stats.dark,
          'changed': stats.changed,
          'skipped': stats.skipped,
      }

      playbook_info = {
          'timestamp': str(datetime.datetime.now()),
          'state': 'playbook_end',
          'deployment_name': os.environ.get('ANSIBLE_DEPLOYMENT_NAME'),
          'playbook_stats': playbook_stats,
      }

      self.send_gcp_log(playbook_info)
    except:  # pylint: disable=bare-except
      logging.exception(
          'An error occurred while trying to send final playbook stats.'
      )
