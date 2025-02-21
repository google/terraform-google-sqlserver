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

configuration ConfigurationWorkload {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ComputerName,

        [Parameter(Mandatory = $true)]
        [string] $SQLSecretName,

        [Parameter(Mandatory = $true)]
        [string] $ADSecretName,

        [Parameter(Mandatory = $false)]
        [PSCustomObject] $Parameters
    );

    $adPassword = ConvertTo-SecureString -String (gcloud secrets versions access latest --secret=$ADSecretName) -AsPlainText -Force;
    $domainCredential = New-Object System.Management.Automation.PSCredential ("$($Parameters.domainName)\Administrator", $adPassword);

    Import-DscResource -ModuleName PSDesiredStateConfiguration, SqlServerDsc, ComputerManagementDsc, ActiveDirectoryDsc, NetworkingDsc

    # Disable firewall profiles
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

    # Set DNS address
    $nic = Get-NetAdapter
    Set-DnsClientServerAddress -InterfaceIndex $nic[0].ifIndex -ServerAddresses ($Parameters.domainIp)

    # Setup credentials
    $credentialAdmin = New-Object System.Management.Automation.PSCredential ('Administrator', $adPassword);
    $credentialAdminDomain = New-Object System.Management.Automation.PSCredential ("$($Parameters.domainName)\Administrator", $adPassword);

    node $ComputerName {
        WaitForADDomain 'WFAD' {
            DomainName  = $Parameters.domainName
            Credential = $domainCredential
            RestartCount = 2
        }

        Computer 'JoinDomain' {
            Name = $Node.NodeName
            DomainName = $Parameters.domainName
            Credential = $domainCredential
            DependsOn = '[WaitForADDomain]WFAD'
        }

        WindowsFeature 'FSFileServer' {
            Ensure    = 'Present'
            Name      = 'FS-FileServer'
        }

        File 'Witness' {
            DestinationPath = 'C:\QWitness'
            Type = 'Directory' # pslint: disable
        }

        File 'Backup' {
            DestinationPath = 'C:\Backup'
            Type = 'Directory' # pslint: disable
        }

        SmbShare 'Witness' {
            Name = 'QWitness'
            Path = 'C:\QWitness'
            EncryptData = $false
            FolderEnumerationMode = 'Unrestricted'
            CachingMode = 'None'
            ContinuouslyAvailable = $false
            FullAccess = @(
                "$($Parameters.domainName)\Domain Computers",
                "$($Parameters.domainName)\Domain Admins"
            )
            DependsOn = '[File]Witness'
        }

        SmbShare 'Backup' {
            Name = 'Backup'
            Path = 'C:\Backup'
            EncryptData = $false
            FolderEnumerationMode = 'Unrestricted'
            CachingMode = 'None'
            ContinuouslyAvailable = $false
            FullAccess = @(
                "$($Parameters.domainName)\Domain Computers",
                "$($Parameters.domainName)\Domain Admins"
            )
            DependsOn = '[File]Backup'
        }

        Registry 'AddDscRegistryKey' {
            Ensure = 'Present'
            Key = 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Google\WorkloadManager\SQLServerDeployment'
            ValueName = 'InitialConfiguration'
            ValueData = 1
            ValueType = 'Binary'
            DependsOn = '[SmbShare]Backup'
        }
    }
}