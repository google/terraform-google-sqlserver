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

$deploymentName = '${deploymentName}';
$nameHost = '${nameHost}'
$isFirst = '${isFirst}'
$deploymentTimeout = '${deploymentTimeout1}'
$globalDeploymentTimeout = '${deploymentTimeout2}'
$zone = '${zone}'
enum StatusCode {
    Running = 1
    Success = 2
    Timeout = 3
    GlobalTimeout = 4
}
$configureLocalSSD = @'
$isLocalSsd = '${isLocalSsd}';
function Get-LocalSsdDrive {

    $vol = Get-Volume -FileSystemLabel 'TEMPDB' -ErrorAction Ignore

    if ($null -ne $vol) {
        return $vol.DriveLetter
    }

    # Get the first available letter (starting F) for localSSD drive
    $diskNumber = 'F'
    $isNumberUsed = Get-PSDrive -Name $diskNumber -ErrorAction SilentlyContinue
    if ($isNumberUsed) {
        # Find the first available drive letter
        $availableDrives = [char[]] (70..90) | Where-Object { !(Get-PSDrive $_ -ErrorAction SilentlyContinue) }
        $diskNumber = $availableDrives | Select-Object -First 1
    }
    return $diskNumber
}

$registryPath = 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Google\WorkloadManager\SQLServerDeployment'
$keyName = 'InitialConfiguration'
$keyValue = Get-ItemProperty -Path $registryPath -Name $keyName -ErrorAction SilentlyContinue
if ($keyValue -eq $null -or $keyValue.InitialConfiguration -ne 1) {
    return
}
$localSsdDrive = Get-LocalSsdDrive
$localSSDNames = 'Google EphemeralDisk', 'NVMe nvme_card', 'nvme_card'
$vol = Get-Volume | Where-Object {$_.FileSystemLabel -eq 'TEMPDB'}

if ($isLocalSsd -eq $true -and $vol -eq $null) {
    # Prepare the local SSD
    $physicalDisks = Get-PhysicalDisk | Where-Object {$_.CanPool -eq $true -and $localSSDNames -contains $_.FriendlyName} | Select-Object -exp DeviceID | Sort-Object | Get-Unique
    if (@($physicalDisks).Count -gt 0) {
        if (@($physicalDisks).Count -gt 1) {
            foreach($disk in $physicalDisks) {
                @(\"select disk $($disk)\", \"online disk noerr\", \"attributes disk clear readonly\", \"clean\", \"convert gpt\", \"convert dynamic\") | diskpart
            }

            $disks = $physicalDisks -Join ','
            @(\"create volume stripe disk=$disks\", \"format fs=ntfs quick unit=64k label=TEMPDB\", \"assign letter=$localSSDDrive\") | diskpart

        }
        else {
            # Find the unbooted local SSD
            $localSSD = Get-Disk | Where-Object {
                $_.IsBoot -eq $false -and
                $_.PartitionStyle -eq 'RAW' -and
                $localSSDNames -contains $_.FriendlyName
            }

            if ($localSSD -ne $null) {
                Write-Output 'Initializing the local SSD...'
                Initialize-Disk -Number $localSSD.Number -PartitionStyle GPT
            }

            $localSSD = Get-Disk | Where-Object {
                $_.IsBoot -eq $false -and
                $_.PartitionStyle -eq 'GPT' -and
                $localSSDNames -contains $_.FriendlyName
            }

            $partition = Get-Partition -DiskNumber $localSSD.Number | Where-Object { [int]$_.DriveLetter -ge 70 } | Select-Object -First 1

            if ($null -eq $partition) {
                # Create a new partition using all available space
                $partition = New-Partition -DiskNumber $localSSD.Number -UseMaximumSize -DriveLetter $localSSDDrive
            }
            else {
                $localSSDDrive = $partition.DriveLetter
            }

            if ((Get-Volume -DriveLetter $partition.DriveLetter).FileSystemType -ne 'NTFS') {
                # Format the partition (NTFS)
                Format-Volume -DriveLetter $partition.DriveLetter -FileSystem NTFS -NewFileSystemLabel 'TEMPDB' -Confirm:$false
                Write-Output \"Formatted the local SSD $($localSsdDrive)\"
            }
        }
        $diskName = \"$($localSSDDrive):\"
        $acl = Get-ACL $diskName
        $accessRule= New-Object System.Security.AccessControl.FileSystemAccessRule('everyone','FullControl','ContainerInherit,Objectinherit','none','Allow')
        $acl.AddAccessRule($accessRule)
        # Set folder permission
        Set-Acl $diskName $acl

        # Create tempDB folder
        $tempdbTargetDir = \"$($LocalSsdDrive):\SQLData\"
        if (-not(Test-Path $tempdbTargetDir)) {
            New-Item -Path $tempdbTargetDir -ItemType directory;
        }
        $service = Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
        if ($service -ne $null) {
            # Restart the SQL Server service
            Start-Service -Name MSSQLSERVER
        }
    }
}
'@

function Log-DscState {
    param (
      [string] $state,
      [string] $error
    )
    $message = @{
        baseDir = $PSCommandPath;
        state = $state;
        playbook_stats = @{
            'failures' = @{};
        };
        deployment_name = $deploymentName;
        instance_name = $nameHost;
        time = (Get-Date).ToString();
    }
    if ($error -ne $null -and $error -ne '') {
        $message.playbook_stats['failures'].Add($nameHost, $error);
    }
    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload $message
}

function Log-SqlDeploymentUsageMetrics {
    param (
      [string] $state
    )
    $service = Get-Service -Name 'google-cloud-workload-agent' -ErrorAction SilentlyContinue
    if ($service.Status -eq 'Running') {
        $pathWithArgs = (Get-CimInstance Win32_Service -Filter "Name='google-cloud-workload-agent'").PathName
        $path = $pathWithArgs.Substring(0, $pathWithArgs.IndexOf('winservice') - 1)
        $executionPath = $path.Trim('"')
        # DSC first execution end
        Start-Process $executionPath -ArgumentList 'logusage','-s','ACTION', '-a', $state
    }
    else {
        Write-Host 'Workload agent is not running.'
        New-GcLogEntry -LogName 'Ansible_logs' -TextPayload 'Workload agent is not running.'
    }
}

# Log google cloud SQL server agent metrics and replace the startup script
function Run-PostDeploymentSteps {
    param (
      [string] $stateName
    )
    Log-SqlDeploymentUsageMetrics -state ([StatusCode]::$stateName.value__)
    gcloud compute instances add-metadata $nameHost --zone=$zone --metadata ^~^windows-startup-script-ps1=$configureLocalSSD
}

$registryPath = 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Google\WorkloadManager\SQLServerDeployment'
$keyName = 'InitialConfiguration'

$maxLoopDuration = $deploymentTimeout
$startTime = Get-Date
$dscStartTime = Get-ItemProperty -Path $registryPath -Name 'DscStartTime' -ErrorAction SilentlyContinue
while ($isFirst -eq $true) {
    $elapsedTime = (Get-Date) - $startTime
    $elapsedSeconds = $elapsedTime.TotalSeconds

    if ($dscStartTime -ne $null) {
        $dscElapsedTime = (Get-Date) - $dscStartTime
        $dscElapsedSeconds = $dscElapsedTime.TotalSeconds
        if ($dscElapsedSeconds -gt $globalDeploymentTimeout) {
            Log-DscState -state 'playbook_end' -error "Timeout after $globalDeploymentTimeout seconds"
            Run-PostDeploymentSteps -stateName 'GlobalTimeout'
            break
        }
    }

    if ($elapsedSeconds -gt $maxLoopDuration) {
        Log-DscState -state 'playbook_end' -error "Timeout after $maxLoopDuration seconds"
        Run-PostDeploymentSteps -stateName 'Timeout'
        break
    }

    $registryValue = Get-ItemProperty -Path $registryPath -Name $keyName -ErrorAction SilentlyContinue
    if ($registryValue -and $registryValue.InitialConfiguration -eq 1) {
        Log-DscState -state 'playbook_end'
        Run-PostDeploymentSteps -stateName 'Success'
        break
    }

    Log-DscState -state 'playbook_running'
    Write-Output 'Sleeping for 60 seconds'
    Start-Sleep -Seconds 60
}