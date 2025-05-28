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

$global:localSSDNames = 'Google EphemeralDisk', 'NVMe nvme_card', 'nvme_card'

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

Configuration ConfigurationWorkload {
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $ComputerName,

        [Parameter(Mandatory = $true)]
        [string] $SQLSecretName,

        [Parameter(Mandatory = $true)]
        [string] $ADSecretName,

        [Parameter(Mandatory = $false)]
        [PSCustomObject] $Parameters
    );

    <#
        Please see go/wlm4sqlserver-deployment-dscmodules for dsc module to deployment mapping.
        Mask:
            Multi-writer: 8
            S2D: 4
            AOAG: 2
            Single Instance: 1
    #>
    $dscBlocks = @{
        WindowsFeature = 6 # 0110
        DotNetFramework45 = 7 # 0111
        WFAD = 7 # 0111
        JoinDomain = 7 # 0111
        SQLAdminAccount = 2 # 0010
        PrepareScratchDisks = 7 # 0111
        PrepareDataDisk = 3 # 0011
        PrepareLogDisk = 3 # 0011
        InstallDefaultInstance = 3 # 0011
        SqlServerFirewall = 1 # 0001
        MoveDatabaseFiles = 3 # 0011
        Witness = 6 # 0110
        CreateCluster = 6 # 0110
        Quorum = 6 # 0110
        EnableAOAG = 2 # 0010
        HADREndPoint = 2 # 0010
        DatabaseMirroringLogin = 2 # 0010
        SQLEndpointPermission = 2 # 0010
        AddAG = 2 # 0010
        WaitAllForJoinAOAG = 2 # 0010
        SetupDNN = 2 # 0010
        SetupDNNFCI = 4 # 0100
        AddDNNPermission = 2 # 0010
        CreateSampleDatabase = 2 # 0010
        AddSampleDatabaseToAOAG = 2 # 0010
        WaitAllForCreateAOAG = 2 # 0010
        AddReplica = 2 # 0010
        UninstallExistingMSSQL = 4 # 0100
        RebootAfterSQLSrvUninstall = 4 # 0100
        PrestageClusterResource = 4 # 0100
        AddClusterResourceToGroup = 4 # 0100
        GrantCNOFullControl = 4 # 0100
        EnableStorageSpacesDirect = 4 # 0100
        CreateVolume = 4 # 0100
        SqlServerSetup = 4 # 0100
        FciFirstNodeSetup = 4 # 0100
        WaitFciFirstNodeSetup = 4 # 0100
        WaitForCluster = 4 # 0100
        AddSysAdminAccount = 7 # 0111
        AddSystemUserACcount = 2 # 0010
        RestoreSampleDatabase = 2 # 0010
        InstallCloudSqlAgent = 7 # 0111
        AddDscRegistryKey = 7 # 0111
        AddRegistryKeyDscStart = 7 # 0111
    }

    $deploymentMask = $parameters.mask
    $witnessName = "$($Parameters.vmPrefix)-w-0"
    $node1 = "$($Parameters.vmPrefix)-0"
    $node2 = "$($Parameters.vmPrefix)-1"
    $dnnPort = '1533'
    $dnnName = "$($Parameters.vmPrefix)-dnn"

    $splitResult = $Parameters.domainName.Split('.')
    $domainSLD = $splitResult[0]
    $domainPath = $Parameters.domainName.Replace('.', ',DC=')
    $domainPath = 'DC=' + $domainPath
    $localSsdDrive = Get-LocalSsdDrive
    $isLocalSsd = $Parameters.isLocalSsd
    $localSSDNames = $global:localSSDNames
    $deploymentName = $parameters.deploymentName

    $sqlFolderName = 'C:\sql_server_install'
    $sqlRootDir = 'C:\Program Files\Microsoft SQL Server'

    $failoverClusterName = "$($Parameters.vmPrefix)-cluster"

    $sqlPassword = ConvertTo-SecureString -String (gcloud secrets versions access latest --secret=$SQLSecretName) -AsPlainText -Force;
    $adPassword = ConvertTo-SecureString -String (gcloud secrets versions access latest --secret=$ADSecretName) -AsPlainText -Force;
    $domainCredential = New-Object System.Management.Automation.PSCredential ("$($Parameters.domainName)\$($Parameters.adUsername)", $adPassword);
    $sqlCredential = New-Object System.Management.Automation.PSCredential ('sa', $sqlPassword);

    $domainUserName = $domainCredential.UserName
    $passwordPlain = $domainCredential.GetNetworkCredential().password

    $databaseName = 'bookshelf'
    $agName = "$($Parameters.vmPrefix)-ag"
    $osVersion = [int]((systeminfo | findstr /B /C:'OS Name') -replace '[^0-9]','')

    if ($isLocalSsd) {
        $tempdbTargetDir = "$($LocalSsdDrive):\SQLData"
    }
    else {
        $tempdbTargetDir = $null
    }

    # Check if SQL server is already installed
    if (-not (Test-Path -Path $sqlRootDir)) {
        if (-not (Test-Path -Path $sqlFolderName)) {

            New-Item -Path C:\Temp -ItemType Directory
            New-Item -Path $sqlFolderName -ItemType Directory
        }
    }

    # If media bucket is present, use the iso file in the bucket to install SQL server
    if ($Parameters.isoBucket -and -not (Test-Path "$sqlFolderName\setup.exe")) {
        # Get the first iso file in the specified bucket
        $isoImagePath = gsutil ls gs://$($Parameters.isoBucket)/*.iso

        $tempErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        gsutil cp -n $isoImagePath c:\temp
        $ErrorActionPreference = $tempErrorActionPreference

        $isoImage = ($isoImagePath -split '\/')[-1]
        $mountResult = Mount-DiskImage -ImagePath "C:\temp\$isoImage" -PassThru

        $volumeInfo = $mountResult | Get-Volume
        $driveInfo = Get-PSDrive -Name $volumeInfo.DriveLetter
        Copy-Item -Path ( Join-Path -Path $driveInfo.Root -ChildPath '*' ) -Destination $sqlFolderName -Recurse
        Dismount-DiskImage -ImagePath "C:\temp\$isoImage"
    }

    # Disable firewall
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

    # Set DNS address
    $nic = Get-NetAdapter
    Set-DnsClientServerAddress -InterfaceIndex $nic[0].ifIndex -ServerAddresses ($Parameters.domainIp)

    Start-Sleep -Seconds 60

    Import-DscResource -ModuleName PSDesiredStateConfiguration, SqlServerDsc, ComputerManagementDsc, ActiveDirectoryDsc, NetworkingDsc, FailoverClusterDsc

    $features = @(
      'Failover-clustering',
      'FS-FileServer',
      'Storage-Replica',
      'RSAT-Clustering-PowerShell',
      'RSAT-Clustering-CmdInterface',
      'RSAT-Clustering-Mgmt',
      'RSAT-Storage-Replica',
      'RSAT-AD-PowerShell'
    );

    node $ComputerName {
        if ($dscBlocks.AddRegistryKeyDscStart -band $deploymentMask) {
            $startTime = (Get-Date).ToString()
            Registry 'AddRegistryKeyDscStart' {
                Ensure = 'Present'
                Key = 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Google\WorkloadManager\SQLServerDeployment'
                ValueName = 'ConfigurationStartTime'
                ValueData = $startTime
                ValueType = 'String'
            }
        }

        if ($dscBlocks.WindowsFeature -band $deploymentMask) {
            foreach($feature in $features) {
                WindowsFeature ('WF-'+$feature) {
                    Name = $feature
                    Ensure = 'Present'
                }
            }
        }

        if ($dscBlocks.DotNetFramework45 -band $deploymentMask) {
            WindowsFeature 'NetFramework45' {
                Name   = 'NET-Framework-45-Core'
                Ensure = 'Present'
            }
        }

        if ($dscBlocks.WFAD -band $deploymentMask) {
            WaitForADDomain 'WFAD' {
                DomainName  = $Parameters.domainName
                Credential = $domainCredential
                RestartCount = 2
            }
        }

        if ($dscBlocks.JoinDomain -band $deploymentMask) {
            Computer 'JoinDomain' {
                Name = $Node.NodeName
                DomainName = $Parameters.domainName
                Credential = $domainCredential
                DependsOn = '[WaitForADDomain]WFAD'
            }
        }

        if ($dscBlocks.SQLAdminAccount -band $deploymentMask) {
            ADUser 'SQLAdminAccount' {
                DomainName = $Parameters.domainName
                UserPrincipalName = "sql_server@$($Parameters.domainName)"
                Credential = $domainCredential
                UserName = 'sql_server'
                Password = $domainCredential
                PasswordNeverExpires = $true
                Ensure = 'Present'
            }
        }

        if ($dscBlocks.PrepareScratchDisks -band $deploymentMask) {
            Script 'PrepareScratchDisks' {
                GetScript  = {
                    if ($using:isLocalSsd -eq $false) { return @{Ensure = 'Present' }; }

                    if ($null -ne (Get-Volume -FileSystemLabel 'TEMPDB' -ErrorAction Ignore)) {
                        return @{Ensure = 'Present' };
                    }
                    else {
                        return @{Ensure = 'Absent' };
                    }
                }
                TestScript = {
                    $state = [scriptblock]::Create($GetScript).Invoke();
                    return $state.Ensure -eq 'Present';
                }
                SetScript  = {
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'Begin LocalSSD configuration';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }

                    $localSSDDrive = $using:localSsdDrive
                    try {
                        $physicalDisks = Get-PhysicalDisk | Where-Object {$_.CanPool -eq $true -and $using:localSSDNames -contains $_.FriendlyName} | Select-Object -exp DeviceID | Sort-Object | Get-Unique
                    }
                    catch {
                        $errorMessage = "Error enumerating physical disks. Error: $($_.Exception.Message)"
                        $logPayload = @{
                            deployment_name = $using:deploymentName;
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                            dsc_resource  = 'PrepareScratchDisks';
                            operation = 'GetPhysicalDisksForPooling'
                            status = 'ERROR';
                            error_message = $errorMessage;
                            suggested_remediation = "Verify the user:$($using:domainUserName) has admin rights to query physical disks. Check system event logs."
                        }
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload $logPayload
                        throw $errorMessage
                    }
                    if (@($physicalDisks).Count -gt 0) {
                        if (@($physicalDisks).Count -gt 1) {
                            try {
                                foreach($disk in $physicalDisks) {
                                    @("select disk $($disk)", "online disk noerr", "attributes disk clear readonly", "clean", "convert gpt", "convert dynamic") | diskpart
                                }

                                $disks = $physicalDisks -Join ','
                                @("create volume stripe disk=$disks", "format fs=ntfs quick unit=64k label=TEMPDB", "assign letter=$localSSDDrive") | diskpart
                            } catch {
                                $errorMessage = "Error during diskpart operation: $($_.Exception.Message). This might also indicate an issue with diskpart itself or the commands sent."
                                New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                    deployment_name = $using:deploymentName;
                                    time = (Get-Date).ToString();
                                    instance_name = $using:ComputerName;
                                    dsc_resource = 'PrepareScratchDisks';
                                    operation = 'DiskpartOperation';
                                    status = 'ERROR';
                                    error_message = $errorMessage;
                                    suggested_remediation = 'Review diskpart commands and disk states. Check Disk Management console for errors. Ensure disks were available and not in use.'
                                }
                                throw $errorMessage
                            }
                        }
                        else {
                            # Find the unbooted local SSD
                            $localSSD = Get-Disk | Where-Object {
                                $_.IsBoot -eq $false -and
                                $_.PartitionStyle -eq 'RAW' -and
                                $using:localSSDNames -contains $_.FriendlyName
                            }

                            if ($localSSD -ne $null) {
                                Write-Output 'Initializing the local SSD...'
                                Initialize-Disk -Number $localSSD.Number -PartitionStyle GPT
                            }

                            $localSSD = Get-Disk | Where-Object {
                                $_.IsBoot -eq $false -and
                                $_.PartitionStyle -eq 'GPT' -and
                                $using:localSSDNames -contains $_.FriendlyName
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
                                Write-Output "Formatted the local SSD: $($using:localSsdDrive)"
                            }
                        }
                    }
                    $diskName = "$($localSSDDrive):"
                    $acl = Get-ACL $diskName
                    $accessRule= New-Object System.Security.AccessControl.FileSystemAccessRule('everyone','FullControl','ContainerInherit,Objectinherit','none','Allow')
                    $acl.AddAccessRule($accessRule)
                    try {
                        # Set folder permission
                        Set-Acl $diskName $acl
                    } catch {
                        $errorMessage = "Error setting ACL for path '$diskName': $($_.Exception.Message)"
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName;
                            times = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                            dsc_resource = 'PrepareScratchDisks';
                            operation = 'SetACL'
                            status = 'ERROR';
                            error_message = $errorMessage;
                            suggested_remediation = "Verify the user:$($using:domainUserName) has admin rights to modify ACLs on '$diskName'."
                        }
                        throw $errorMessage
                    }
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'End LocalSSD configuration';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                }
                PsDscRunAsCredential = $domainCredential
                DependsOn            = '[Computer]JoinDomain'
            }
        }

        if ($dscBlocks.PrepareDataDisk -band $deploymentMask) {
            Script 'PrepareDataDisk' {
                GetScript  = {
                    if (Test-Path 'D:\Data') {
                    $result = 'Present';
                    }
                    else {
                    $result = 'Absent';
                    }
                    return @{Ensure = $result };
                }
                TestScript = {
                    $state = [scriptblock]::Create($GetScript).Invoke();
                    return $state.Ensure -eq 'Present';
                }
                SetScript  = {
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'Begin data disk configuration';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                    # Select the largest sized RAW disk
                    $rawDiskNumber = (Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'} | Sort-Object -Property Size -Descending | Select-Object -Property Number -First 1).Number

                    if ($rawDiskNumber -ne $null) {
                        # Format data disk
                        Initialize-Disk -Number $rawDiskNumber -PartitionStyle MBR -PassThru
                        New-Partition -DiskNumber $rawDiskNumber -DriveLetter 'D' -UseMaximumSize
                        Format-Volume -DriveLetter 'D' -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel 'Data' -Confirm:$false
                    }

                    # Create data and log folders for SQL Server
                    New-Item -Path 'D:\Data'  -ItemType directory;
                    Write-Output 'Formatted the data disk: D:'

                    $acl = Get-ACL 'D:'
                    $accessRule= New-Object System.Security.AccessControl.FileSystemAccessRule('everyone','FullControl','ContainerInherit,Objectinherit','none','Allow')
                    $acl.AddAccessRule($accessRule)
                    try {
                        # Set folder permission
                        Set-Acl 'D:' $acl
                    } catch {
                        $errorMessage = "Error setting ACL for path 'D:': $($_.Exception.Message)"
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName;
                            times = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                            dsc_resource = 'PrepareDataDisks';
                            operation = 'SetACL'
                            status = 'ERROR';
                            error_message = $errorMessage;
                            suggested_remediation = "Verify the user:$($using:domainUserName) has admin rights to modify ACLs on 'D:'."
                        }
                        throw $errorMessage
                    }
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'End data disk configuration';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                }
                PsDscRunAsCredential = $domainCredential
                DependsOn            = '[WindowsFeature]NetFramework45'
            }
        }

        if ($dscBlocks.PrepareLogDisk -band $deploymentMask) {
            Script 'PrepareLogDisk' {
                GetScript  = {
                    if (Test-Path 'E:\Logs') {
                    $result = 'Present';
                    }
                    else {
                    $result = 'Absent';
                    }
                    return @{Ensure = $result };
                }
                TestScript = {
                    $state = [scriptblock]::Create($GetScript).Invoke();
                    return $state.Ensure -eq 'Present';
                }
                SetScript  = {
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'Begin data disk configuration';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                    # Select the largest sized RAW disk
                    $rawDiskNumber = (Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'} | Sort-Object -Property Size -Descending | Select-Object -Property Number -First 1).Number

                    if ($rawDiskNumber -ne $null) {
                        # Format log disk
                        Initialize-Disk -Number $rawDiskNumber -PartitionStyle MBR -PassThru
                        New-Partition -DiskNumber $rawDiskNumber -DriveLetter 'E' -UseMaximumSize
                        Format-Volume -DriveLetter 'E' -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel 'Log' -Confirm:$false
                    }

                    # Create a log folder for SQL Server
                    New-Item -Path 'E:\Logs'  -ItemType directory;
                    Write-Output 'Formatted the log disk: E:'

                    $acl = Get-ACL 'E:'
                    $accessRule= New-Object System.Security.AccessControl.FileSystemAccessRule('everyone','FullControl','ContainerInherit,Objectinherit','none','Allow')
                    $acl.AddAccessRule($accessRule)
                    try {
                        # Set folder permission
                        Set-Acl 'E:' $acl
                    } catch {
                        $errorMessage = "Error setting ACL for path 'E:': $($_.Exception.Message)"
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName;
                            times = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                            dsc_resource = 'PrepareLogDisks';
                            operation = 'SetACL'
                            status = 'ERROR';
                            error_message = $errorMessage;
                            suggested_remediation = "Verify the user:$($using:domainUserName) has admin rights to modify ACLs on 'E:'."
                        }
                        throw $errorMessage
                    }
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'End data disk configuration';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                }
                PsDscRunAsCredential = $domainCredential
                DependsOn            = '[WindowsFeature]NetFramework45'
            }
        }

        if ($dscBlocks.UninstallExistingMSSQL -band $deploymentMask) {
            Script 'UninstallExistingMSSQL' {
                GetScript = {
                    $service = Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
                    $isFCINode = Get-ClusterGroup -Name 'SQL Server (MSSQLSERVER)' -ErrorAction SilentlyContinue

                    if ($service -ne $null -and $isFCINode -ne $null) {
                        $result = 'Uninstalled';
                    }
                    else {
                        $result = 'Installed';
                    }
                    return @{Ensure = $result };
                }
                TestScript = {
                    $state = [scriptblock]::Create($GetScript).Invoke();
                    return $state.Ensure -eq 'Uninstalled';
                }
                SetScript  = {
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'Begin SQL Server Uninstall';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }

                    # Stop the SQL Server service, otherwise the database files may be locked
                    $service = Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue
                    if ($service -ne $null -and $service.Status -eq 'Running') {
                        Stop-Service -Name MSSQLSERVER -Force
                    }

                    # Uninstall OLE drivers
                    if ((Get-Package -Name 'Microsoft OLE*' -ErrorAction SilentlyContinue) -ne $null) {
                        Get-Package -Name 'Microsoft OLE*' | Uninstall-Package -Force
                    }

                    # Uninstall ODBC drivers
                    if ((Get-Package -Name 'Microsoft ODBC*' -ErrorAction SilentlyContinue) -ne $null) {
                        Get-Package -Name 'Microsoft ODBC*' | Uninstall-Package -Force
                    }
                    Start-Process -FilePath 'C:\sql_server_install\Setup.exe' -ArgumentList '/Action=Uninstall /FEATURES=SQL,AS,IS,RS /INSTANCENAME=MSSQLSERVER /Q' -PassThru -Wait

                    # Remove the SQL Server service
                    sc.exe delete MSSQLSERVER

                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'End SQL Server Uninstall';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                }
                PsDscRunAsCredential = $domainCredential
                DependsOn            = '[Computer]JoinDomain'
            }
        }

        if ($dscBlocks.RebootAfterSQLSrvUninstall -band $deploymentMask) {
            PendingReboot RebootAfterSQLSrvUninstall {
                Name       = 'RebootAfterSQLSrvUninstall'
                DependsOn  = '[Script]UninstallExistingMSSQL'
            }
        }

        if ($dscBlocks.InstallDefaultInstance -band $deploymentMask) {
            SqlSetup 'InstallDefaultInstance' {
                InstanceName        = 'MSSQLSERVER'
                Features            = 'SQLENGINE,FULLTEXT'
                SourcePath          = $sqlFolderName
                SQLSysAdminAccounts = @($domainSLD + '\' + $Parameters.adUsername)
                TcpEnabled          = $true
                NpEnabled           = $true
                UpdateEnabled       = 'False'
                SQLSvcAccount        = $domainCredential
                SQLUserDBDir        = 'D:\Data'
                SQLUserDBLogDir     = 'E:\Logs'
                SQLTempDBDir        = $tempdbTargetDir
                SQLTempDBLogDir     = $tempdbTargetDir
                DependsOn           = '[Script]PrepareDataDisk', '[Script]PrepareScratchDisks'
            }
        }

        if ($dscBlocks.AddSystemUserACcount -band $deploymentMask) {
            SqlLogin 'AddSystemUserToMasterDB' {
                Ensure               = 'Present'
                Name                 = 'NT AUTHORITY\SYSTEM'
                LoginType            = 'WindowsUser'
                ServerName           = $Node.NodeName
                InstanceName         = 'MSSQLSERVER'
                DefaultDatabase      = 'master'
                DependsOn            = '[SqlSetup]InstallDefaultInstance'
            }

            SqlPermission 'AddSystemUserPermissions' {
                ServerName   = $Node.NodeName
                InstanceName = 'MSSQLSERVER'
                Principal         = 'NT AUTHORITY\SYSTEM'
                PsDscRunAsCredential   = $domainCredential
                Permission   = @('AlterAnyAvailabilityGroup', 'ViewServerState', 'ConnectSql')
                DependsOn = '[SqlLogin]AddSystemUserToMasterDB'
            }
        }

        if ($dscBlocks.SqlServerFirewall -band $deploymentMask) {
            SqlWindowsFirewall 'SqlServerFirewall' {
                SourcePath = $sqlFolderName
                InstanceName = 'MSSQLSERVER'
                Features = 'SQLENGINE,FULLTEXT'
                DependsOn = '[SqlSetup]InstallDefaultInstance'
            }
        }

        if ($dscBlocks.MoveDatabaseFiles -band $deploymentMask) {
            Script 'MoveDatabaseFiles' {
                GetScript = {
                    $result =
                        & 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe' -S localhost  -Q 'SELECT name, physical_name FROM sys.master_files;' -b
                    Write-Output $result
                }
                TestScript = {
                    # Ensure SQL Server service is running
                    $service = Get-Service -Name MSSQLSERVER
                    if ($service.Status -ne 'Running') {
                        Write-Error 'SQL Server service is not running.'
                        return $false
                    }

                    # Check if files exist in the new locations
                    $dataPath = 'D:\Data'
                    $logPath = 'E:\Logs'
                    $expectedFiles = @{
                        $dataPath = @('model.mdf', 'msdbdata.mdf','master.mdf')
                        $logPath = @('modellog.ldf', 'msdblog.ldf', 'mastlog.ldf')
                    }

                    foreach ($path in $expectedFiles.Keys) {
                        foreach ($file in $expectedFiles[$path]) {
                            $filePath = Join-Path $path $file
                            if (-not (Test-Path $filePath)) {
                                return $false
                            }
                        }
                    }
                    # All checks passed
                    return $true
                }

                SetScript = {
                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'Begin system database file location update';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }

                    $queryToMoveFiles = "
                    ALTER DATABASE model MODIFY FILE (NAME = modeldev, FILENAME = 'D:\Data\model.mdf');
                    ALTER DATABASE model MODIFY FILE (NAME = modellog, FILENAME = 'E:\Logs\modellog.ldf');
                    ALTER DATABASE msdb MODIFY FILE (NAME = MSDBData, FILENAME = 'D:\Data\msdbdata.mdf');
                    ALTER DATABASE msdb MODIFY FILE (NAME = MSDBLog, FILENAME = 'E:\Logs\msdblog.ldf');"
                    & 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe' -S localhost  -Q $queryToMoveFiles

                    $instanceName = 'MSSQLSERVER'
                    # Get the registry key path for the instance startup parameters
                    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*\MSSQLServer\Parameters'
                    # Set the updated startup parameters
                    Set-ItemProperty -Path $keyPath -Name 'SQLArg0' -Value '-dD:\Data\master.mdf'
                    Set-ItemProperty -Path $keyPath -Name 'SQLArg2' -Value '-lE:\Logs\mastlog.ldf'

                    if ($using:isLocalSsd) {
                        # Create tempDB folder
                        if (-not(Test-Path $using:tempdbTargetDir)) {
                            New-Item -Path $using:tempdbTargetDir -ItemType directory;
                        }
                        # Move tempDB
                        $sqlStatement = [string]::Format('SELECT ''ALTER DATABASE tempdb MODIFY FILE (NAME = ['' + f.name + ''], '' + ''FILENAME = ''''{0}\'' + f.name + CASE WHEN f.type = 1 THEN ''.ldf'' ELSE ''.mdf'' END + '''''');'' FROM sys.master_files f WHERE f.database_id = DB_ID(N''tempdb'');', $using:tempdbTargetDir)
                        $statements = Invoke-SqlCmd -Query $sqlStatement -TrustServerCertificate | Select-Object Column1 | Foreach-Object {$_.Column1}
                        foreach ($statement in $statements) {
                            Invoke-Sqlcmd -Query $statement -TrustServerCertificate
                        }
                    }

                    # Stop the SQL Server service
                    $service = Get-Service -Name MSSQLSERVER
                    if ($service.Status -eq 'Running') {
                        Stop-Service -Name MSSQLSERVER -Force
                    }

                    # Physically move the files
                    Move-Item 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\model.mdf' 'D:\Data' -Force
                    Move-Item 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\modellog.ldf' 'E:\Logs' -Force
                    Move-Item 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\msdbdata.mdf' 'D:\Data' -Force
                    Move-Item 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\msdblog.ldf' 'E:\Logs' -Force
                    Move-Item 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\master.mdf' 'D:\Data' -Force
                    Move-Item 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\mastlog.ldf' 'E:\Logs' -Force

                    # Restart the SQL Server service
                    Start-Service -Name MSSQLSERVER

                    New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                        deployment_name = $using:deploymentName
                        state = 'End system database file location update';
                        time = (Get-Date).ToString();
                        instance_name = $using:ComputerName;
                    }
                }
                DependsOn = '[SqlSetup]InstallDefaultInstance', '[Script]PrepareDataDisk'
            }
        }

        if ($dscBlocks.HADREndPoint -band $deploymentMask) {
            SqlEndpoint 'HADREndpoint' {
                EndPointName         = 'HADR'
                EndpointType         = 'DatabaseMirroring'
                Ensure               = 'Present'
                Port                 = 5022
                InstanceName         = 'MSSQLSERVER'
                PsDscRunAsCredential = $domainCredential
            }
        }

        if ($Parameters.isFirst) {
            if ($dscBlocks.InstallCloudSqlAgent -band $deploymentMask) {
                Script 'InstallCloudSqlAgent' {
                    GetScript = {
                        $result = 'Absent'
                        $service = Get-Service -Name 'google-cloud-workload-agent' -ErrorAction SilentlyContinue
                        if ($service.Status -eq 'Running') {
                            $result = 'Present';
                        }
                        return @{Ensure = $result};
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin Google Cloud Agent for Compute Workloads installation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                        googet addrepo google-cloud-workload-agent https://packages.cloud.google.com/yuck/repos/google-cloud-workload-agent-windows-x86_64
                        googet -noconfirm install google-cloud-workload-agent

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End Google Cloud Agent for Compute Workloads installation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    PsDscRunAsCredential = $domainCredential
                }
            }
            if ($dscBlocks.FciFirstNodeSetup -band $deploymentMask) {
                SqlSetup 'FciFirstNodeSetup' {
                    SourcePath                 = 'C:\sql_server_install'
                    Features                   = 'SQLENGINE,REPLICATION,FULLTEXT'
                    Action                     = 'InstallFailoverCluster'
                    InstanceName               = 'MSSQLSERVER'
                    FailoverClusterNetworkName = $failoverClusterName
                    SQLSysAdminAccounts        = $Parameters.domainName + '\' + $Parameters.adUsername
                    SQLSvcAccount              = $domainCredential
                    AgtSvcAccount              = $domainCredential
                    InstallSharedDir           = 'C:\Program Files\Microsoft SQL Server'
                    InstallSharedWOWDir        = 'C:\Program Files (x86)\Microsoft SQL Server'
                    InstanceDir                = 'C:\Program Files\Microsoft SQL Server'
                    InstallSQLDataDir          = 'C:\ClusterStorage\Data'
                    FailoverClusterIpAddress   = $Parameters.sqlFciIp
                    SkipRule                   = 'Cluster_VerifyForErrors'
                    PsDscRunAsCredential       = $domainCredential
                    DependsOn                  = '[Script]CreateVolume', '[Script]PrepareScratchDisks'
                }
            }

            if ($dscBlocks.Witness -band $deploymentMask) {
                WaitForAll 'Witness' {
                    ResourceName     = '[SmbShare]Witness'
                    NodeName         = $witnessName
                    RetryIntervalSec = 5
                    RetryCount       = 120
                    DependsOn        = '[Computer]JoinDomain'
                }
            }

            if ($dscBlocks.PrestageClusterResource -band $deploymentMask) {
                ADComputer 'PrestageClusterResource' {
                    ComputerName         = ($Parameters.vmPrefix+'-cl')
                    EnabledOnCreation    = $false
                    PsDscRunAsCredential = $domainCredential
                    DependsOn            = '[PendingReboot]RebootAfterSQLSrvUninstall'
                }
            }

            if ($dscBlocks.AddClusterResourceToGroup -band $deploymentMask) {
                ADGroup 'AddClusterResourceToGroup' {
                    GroupName = 'g-ClusterResources'
                    GroupScope = 'Global'
                    Ensure = 'Present'
                    MembersToInclude = ($Parameters.vmPrefix+'-cl$')
                    PsDscRunAsCredential = $domainCredential
                    DependsOn = '[ADComputer]PrestageClusterResource'
                }
            }

            if ($dscBlocks.CreateCluster -band $deploymentMask) {
                $dependsOn = '[WindowsFeature]WF-Failover-clustering'
                if ($deploymentMask -eq 4) {
                    $dependsOn = '[WindowsFeature]WF-Failover-clustering','[ADGroup]AddClusterResourceToGroup'
                }

                Script 'CreateCluster' {
                    GetScript = {
                        $cluster = Get-Cluster -Name ($using:Parameters.vmPrefix+'-cl') -ErrorAction SilentlyContinue;
                        if ($null -ne $cluster) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result};
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin cluster creation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                        try {
                            if ($using:osVersion -ge 2019) {
                                # ManagementPointNetworkType is only available on Windows 2019 and above
                                New-Cluster -Name ($using:Parameters.vmPrefix+'-cl') -Node $using:node1,$using:node2 `
                                    -ManagementPointNetworkType Distributed -NoStorage;
                            }
                            else {
                                New-Cluster -Name ($using:Parameters.vmPrefix+'-cl') -Node $using:node1,$using:node2 -NoStorage;
                            }
                        } catch {
                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName;
                                time = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                                dsc_resource = 'CreateCluster';
                                operation = 'New-Cluster';
                                status = 'ERROR';
                                error_message = 'Error during creating cluster';
                                cluster_name_attempted = $clusterName; nodes_attempted = $nodes;
                                os_version_for_logic = $using:osVersion;
                                suggested_remediation = 'Verify nodes are online, domain-joined, and resolvable. Check network configuration, permissions, and existing cluster status. Review cluster validation report and system event logs on nodes.';
                            }
                            throw $errorMessage
                        }

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End cluster creation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn = $dependsOn
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.Quorum -band $deploymentMask) {
                ClusterQuorum 'Quorum' {
                    IsSingleInstance = 'Yes'
                    Type = 'NodeAndFileShareMajority'
                    Resource = ('\\'+$witnessName+'\QWitness')
                    PsDscRunAsCredential = $domainCredential
                    DependsOn = '[Script]CreateCluster'
                }
            }

            if ($dscBlocks.EnableAOAG -band $deploymentMask) {
                Script 'EnableAOAG' {
                    GetScript = {
                        $isHadrEnabled = (Invoke-Sqlcmd -Query 'SELECT SERVERPROPERTY(''IsHadrEnabled'') AS IsHadrEnabled' -ServerInstance 'localhost' -TrustServerCertificate).IsHadrEnabled
                        if ($isHadrEnabled -eq 1) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin AOAG configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        try {
                            Test-Cluster
                        } catch {
                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName;
                                times = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                                dsc_resource = 'EnableAOAG';
                                operation = 'Test-Cluster';
                                status = 'ERROR';
                                error_message = "Error during Test-Cluster: $($_.Exception.Message)";
                                suggested_remediation = 'Review the Test-Cluster report at C:\Windows\Cluster\Reports for more details. Address any validation failures.';
                            }
                            throw $errorMessage
                        }

                        try {
                            Enable-SqlAlwaysOn -ServerInstance $using:node1 -Force
                        } catch {
                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName;
                                time = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                                dsc_resource = 'EnableAOAG';
                                operation = 'Enable-SqlAlwaysOn';
                                status = 'ERROR';
                                error_message = "Error during '$operation' on node1: $($_.Exception.Message)";
                                suggested_remediation = "Ensure SQL Server instance on this node is running and correctly configured. Verify Failover Clustering is enabled for the SQL service. Check SQL Server error logs, Windows Event Logs, and WMI provider status."
                            }
                            throw $errorMessage
                        }
                        try {
                            Enable-SqlAlwaysOn -ServerInstance $using:node2 -Force
                        } catch {
                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName;
                                time = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                                dsc_resource = 'EnableAOAG';
                                operation = 'Enable-SqlAlwaysOn';
                                status = 'ERROR';
                                error_message = "Error during '$operation' on node2: $($_.Exception.Message)";
                                suggested_remediation = "Ensure SQL Server instance on this node is running and correctly configured. Verify Failover Clustering is enabled for the SQL service. Check SQL Server error logs, Windows Event Logs, and WMI provider status."
                            }
                            throw $errorMessage
                        }

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End AOAG configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn            = '[ClusterQuorum]Quorum'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.DatabaseMirroringLogin -band $deploymentMask) {
                SqlLogin 'DatabaseMirroringLogin' {
                    InstanceName = 'MSSQLSERVER'
                    Name = "$($domainSLD)\$($node2)$"
                    LoginType = 'WindowsUser'
                    Ensure = 'Present'
                    DependsOn = '[SqlEndpoint]HADREndpoint'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.SQLEndpointPermission -band $deploymentMask) {
                SqlEndpointPermission 'SQLEndpointPermission' {
                    Ensure               = 'Present'
                    InstanceName         = 'MSSQLSERVER'
                    Name                 = 'HADR'
                    Principal            = "$($domainSLD)\$($node2)$"
                    Permission           = 'CONNECT'
                    DependsOn            = '[SqlLogin]DatabaseMirroringLogin'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.AddAG -band $deploymentMask) {
                SqlAG 'AddAG' {
                    Ensure               = 'Present'
                    Name                 = $agName
                    ServerName           = $Node.NodeName
                    InstanceName         = 'MSSQLSERVER'
                    FailoverMode         = 'Automatic'
                    AvailabilityMode     = 'SynchronousCommit'
                    DependsOn            = '[SqlEndpoint]HADREndpoint', '[Script]EnableAOAG'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.WaitAllForJoinAOAG -band $deploymentMask) {
                WaitForAll 'WaitAllForJoinAOAG' {
                    ResourceName         = '[SqlAGReplica]AddReplica'
                    NodeName             = $node2
                    RetryIntervalSec     = 10
                    RetryCount           = 30
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.SetupDNN -band $deploymentMask) {
                Script 'SetupDNN' {
                    GetScript = {
                        $dnn = Get-ClusterResource -Name $using:dnnPort -ErrorAction SilentlyContinue
                        if ($dnn -ne $null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin DNN configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        # create the DNN resource with the port as the resource name
                        Add-ClusterResource -Name $using:dnnPort -ResourceType 'Distributed Network Name' -Group $using:agName

                        # set the DNS name of the DNN resource
                        Get-ClusterResource -Name $using:dnnPort | Set-ClusterParameter -Name DnsName -Value $using:dnnName

                        # start the DNN resource
                        Start-ClusterResource -Name $using:dnnPort

                        $Dep = Get-ClusterResourceDependency -Resource $using:agName
                        if ( $Dep.DependencyExpression -match '\s*\((.*)\)\s*' ) {
                            $DepStr = "$($Matches.1) or [$using:dnnPort]"
                        }
                        else {
                            $DepStr = "[$using:dnnPort]"
                        }

                        Write-Host $DepStr

                        # add the Dependency from availability group resource to the DNN resource
                        Set-ClusterResourceDependency -Resource $using:agName -Dependency $DepStr

                        #bounce the AG resource
                        Stop-ClusterResource -Name $using:agName
                        Start-ClusterResource -Name $using:agName

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End DNN configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn            = '[WaitForAll]WaitAllForJoinAOAG'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.AddDNNPermission -band $deploymentMask) {
                ADObjectPermissionEntry 'AddDNNPermission' {
                    Ensure                             = 'Present'
                    Path                               = "CN=$($Parameters.vmPrefix)-dnn,CN=Computers,$domainPath"
                    IdentityReference                  = "$($Parameters.domainName)\$($Parameters.vmPrefix)-cl$"
                    ActiveDirectoryRights              = 'GenericAll'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                    PsDscRunAsCredential = $domainCredential
                    Dependson = '[Script]SetupDNN'
                }
            }

            if ($dscBlocks.CreateSampleDatabase -band $deploymentMask) {
                Script 'CreateSampleDatabase' {
                    GetScript = {
                        $db =  Get-SqlDatabase -ServerInstance $using:dnnName | Where-Object {$_.Name.StartsWith($using:databaseName)}
                        if ($db -ne $null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin sample database creation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        Write-Host 'Creating a sample database'

                        $sqlStatement = [string]::Format("
                            -- Create a sample database
                            CREATE DATABASE bookshelf ON PRIMARY (
                            NAME = 'bookshelf',
                            FILENAME='d:\Data\bookshelf.mdf',
                            SIZE = 256MB,
                            MAXSIZE = UNLIMITED,
                            FILEGROWTH = 256MB)
                            LOG ON (
                            NAME = 'bookshelf_log',
                            FILENAME='e:\Logs\bookshelf.ldf',
                            SIZE = 256MB,
                            MAXSIZE = UNLIMITED,
                            FILEGROWTH = 256MB)
                            GO

                            USE [bookshelf]
                            SET ANSI_NULLS ON
                            SET QUOTED_IDENTIFIER ON
                            GO

                            -- Create sample table
                            CREATE TABLE [dbo].[Books] (
                            [Id] [bigint] IDENTITY(1,1) NOT NULL,
                            [Title] [nvarchar](max) NOT NULL,
                            [Author] [nvarchar](max) NULL,
                            [PublishedDate] [datetime] NULL,
                            [ImageUrl] [nvarchar](max) NULL,
                            [Description] [nvarchar](max) NULL,
                            [CreatedById] [nvarchar](max) NULL,
                            CONSTRAINT [PK_dbo.Books] PRIMARY KEY CLUSTERED ([Id] ASC) WITH (
                                PAD_INDEX = OFF,
                                STATISTICS_NORECOMPUTE = OFF,
                                IGNORE_DUP_KEY = OFF,
                                ALLOW_ROW_LOCKS = ON,
                                ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
                            ) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
                            GO

                            -- Create a backup
                            ALTER DATABASE [bookshelf] SET RECOVERY FULL;
                            GO
                            BACKUP DATABASE bookshelf to disk = '\\{0}\Backup\bookshelf.bak' WITH INIT
                            GO", $using:witnessName)
                            Invoke-Sqlcmd -query $sqlStatement -TrustServerCertificate

                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName
                                state = 'End sample database creation';
                                time = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                            }
                    }
                    DependsOn            = '[ADObjectPermissionEntry]AddDNNPermission'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.AddSampleDatabaseToAOAG -band $deploymentMask) {
                Script 'AddSampleDatabaseToAOAG' {
                    GetScript = {
                        $sqlQuery = [string]::Format("
                            SELECT DB_NAME(d.database_id) AS DatabaseName
                            FROM sys.databases AS d
                            INNER JOIN sys.availability_replicas AS ar
                                ON d.replica_id = ar.replica_id
                            INNER JOIN sys.availability_groups AS ag
                                ON ar.group_id = ag.group_id
                            WHERE ag.name = '{0}' AND d.name = 'bookshelf';", $using:agName)
                        $db = Invoke-Sqlcmd -query $sqlQuery -TrustServerCertificate
                        if ($db -ne $null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin sample database AOAG configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        Write-Host 'Adding sample database to AOAG ...'

                        $sampleDatabaseName = (Get-SqlDatabase -ServerInstance $using:dnnName | Where-Object {$_.Name.StartsWith($using:databaseName)} | Select-Object -First 1).Name
                        if ($sampleDatabaseName -ne $null) {
                            $sqlStatement = [string]::Format("
                                -- Add the database to the availability group
                                ALTER AVAILABILITY GROUP [{0}] ADD DATABASE [{1}];", $using:agName, $using:databaseName)
                            Invoke-Sqlcmd -query $sqlStatement -TrustServerCertificate
                        }

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End sample database AOAG configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn            = '[Script]CreateSampleDatabase', '[SQLEndpointPermission]SQLEndpointPermission'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.GrantCNOFullControl -band $deploymentMask) {
                ADObjectPermissionEntry 'GrantCNOFullControl' {
                    Ensure                             = 'Present'
                    Path                               = "CN=Computers,$domainPath"
                    IdentityReference                  = "$($Parameters.domainName)\$($Parameters.vmPrefix)-cl$"
                    ActiveDirectoryRights              = 'GenericAll'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                    PsDscRunAsCredential = $domainCredential
                    Dependson = '[Script]CreateCluster'
                }
            }

            if ($dscBlocks.EnableStorageSpacesDirect -band $deploymentMask) {
                Script 'EnableStorageSpacesDirect' {
                    GetScript = {
                        $state = (Get-ClusterStorageSpacesDirect).State;
                        $pool = Get-StoragePool -FriendlyName 'sqldatapool' -ErrorAction SilentlyContinue;
                        if ($state -eq 'Enabled' -and $Null -ne $pool) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin S2D configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        Enable-ClusterStorageSpacesDirect -PoolFriendlyName 'sqldatapool' -Confirm:$false -Verbose;
                        Test-Cluster;

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End S2D configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn            = '[ADObjectPermissionEntry]GrantCNOFullControl'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.CreateVolume -band $deploymentMask) {
                Script 'CreateVolume' {
                    GetScript = {
                        if ((Get-Volume -FriendlyName 'Data' -ErrorAction Ignore) -ne $Null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript  = {
                        Start-Sleep -Seconds 30
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin shared volume creation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        New-Volume -FriendlyName 'Data' -StoragePoolFriendlyName 'sqldatapool' -AllocationUnitSize 65536 -ProvisioningType 'Fixed' -FileSystem CSVFS_ReFS -UseMaximumSize -ErrorAction Ignore;

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End shared volume creation';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn  = '[Script]EnableStorageSpacesDirect'
                }
            }

            if ($dscBlocks.SetupDNNFCI -band $deploymentMask) {
                Script 'SetupDNNFCI' {
                    GetScript = {
                        $dnn = Get-ClusterResource -Name $using:dnnName -ErrorAction SilentlyContinue
                        if ($dnn -ne $null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin DNN configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                        try {
                            Add-ClusterResource -Name $using:dnnName -ResourceType 'Distributed Network Name' -Group 'SQL Server (MSSQLSERVER)'
                        }
                        catch {
                            $errorMessage = "Error during Add-ClusterResource for DNN '$($using:dnnName)': $($_.Exception.Message)"
                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName;
                                time = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                                dsc_resource = 'SetupDNNFCI';
                                status = 'ERROR';
                                error_message = $errorMessage;
                                suggested_remediation =
                                    "Review Failover Clustering event logs (Application Logs -> Microsoft -> Windows -> FailoverClustering) on all cluster nodes for specific errors. Ensure the account $domainUserName running the script has permissions to create and manage cluster resources."
                            }
                        }
                        Get-ClusterResource -Name $using:dnnName | Set-ClusterParameter -Name DnsName -Value $using:dnnName
                        Start-ClusterResource -Name $using:dnnName

                        # restart sql server instance
                        Restart-Service -Name MSSQLSERVER -Force

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End DNN configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    DependsOn            = '[SqlSetup]FciFirstNodeSetup'
                    PsDscRunAsCredential = $domainCredential
                }
            }
        }
        else {

            if ($dscBlocks.DatabaseMirroringLogin -band $deploymentMask) {
                SqlLogin 'DatabaseMirroringLogin' {
                    InstanceName = 'MSSQLSERVER'
                    Name = "$($domainSLD)\$($node1)$"
                    LoginType = 'WindowsUser'
                    Ensure = 'Present'
                    DependsOn = '[SqlEndpoint]HADREndpoint'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.SQLEndpointPermission -band $deploymentMask) {
                SqlEndpointPermission 'SQLEndpointPermission' {
                    Ensure               = 'Present'
                    InstanceName         = 'MSSQLSERVER'
                    Name                 = 'HADR'
                    Principal            = "$($domainSLD)\$($node1)$"
                    Permission           = 'CONNECT'
                    DependsOn            = '[SqlLogin]DatabaseMirroringLogin'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.WaitAllForCreateAOAG -band $deploymentMask) {
                WaitForAll 'WaitAllForCreateAOAG' {
                    ResourceName = '[SqlAG]AddAG'
                    NodeName = $node1
                    RetryIntervalSec = 10
                    RetryCount = 30
                    PsDscRunAsCredential = $domainCredential
                }
            }

            if ($dscBlocks.AddReplica -band $deploymentMask) {
                SqlAGReplica 'AddReplica' {
                    Ensure                     = 'Present'
                    Name                       = $Node.NodeName
                    AvailabilityGroupName      = $agName
                    ServerName                 = $Node.NodeName
                    InstanceName               = 'MSSQLSERVER'
                    PrimaryReplicaServerName   = $node1
                    PrimaryReplicaInstanceName = 'MSSQLSERVER'
                    ProcessOnlyOnActiveNode    = $true
                    FailoverMode               = 'Automatic'
                    AvailabilityMode           = 'SynchronousCommit'
                    DependsOn                  = '[WaitForAll]WaitAllForCreateAOAG', '[SqlEndpointPermission]SQLEndpointPermission'
                    PsDscRunAsCredential       = $domainCredential
                }
            }

            if ($dscBlocks.WaitForCluster -band $deploymentMask) {
                WaitForCluster 'WaitForCluster' {
                    Name             = ($Parameters.vmPrefix + '-cl')
                    RetryIntervalSec = 10
                    RetryCount       = 60
                    DependsOn        = '[WindowsFeature]WF-RSAT-Clustering-CmdInterface'
                }
            }

            if ($dscBlocks.WaitFciFirstNodeSetup -band $deploymentMask) {
                WaitForAll 'WaitFciFirstNodeSetup' {
                    ResourceName         = '[Script]SetupDNNFCI'
                    NodeName             = $node1
                    RetryIntervalSec     = 10
                    RetryCount           = 30
                    PsDscRunAsCredential = $domainCredential
                    DependsOn            = '[PendingReboot]RebootAfterSQLSrvUninstall'
                }
            }

            if ($dscBlocks.SqlServerSetup -band $deploymentMask) {
                Script 'SqlServerSetup' {
                    GetScript            = {
                        $sqlsrv = Get-Service *sql* | Where-Object { $_.displayname -like '*MSSQLSERVER*' }
                        if ($sqlsrv -ne $null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript           = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript  = {
                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin fci configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        # Add a delay to allow primary node to finish with sql server install and KB updates
                        Start-Sleep -Seconds 90
                        $sqlServerInstaller = ($using:sqlFolderName+'\Setup.exe')
                        $sqlServerInstallationArgumentsString = [string]::Format('/Action=AddNode /UpdateEnabled=False /ENU=True /CONFIRMIPDEPENDENCYCHANGE=false /SQLSVCACCOUNT="{0}" /SQLSVCPASSWORD="{1}" /AGTSVCACCOUNT="{2}" /AGTSVCPASSWORD="{1}" /INSTANCENAME="{3}" /FAILOVERCLUSTERNETWORKNAME="{4}" /FAILOVERCLUSTERIPADDRESSES="IPv4;{5};Cluster Network 1;255.255.240.0" /FAILOVERCLUSTERGROUP="SQL Server (MSSQLSERVER)" /SQLSVCINSTANTFILEINIT="False" /FTSVCACCOUNT="NT Service\MSSQLFDLauncher" /IAcceptSQLServerLicenseTerms=1 /INDICATEPROGRESS /Q',$using:domainUserName, $using:passwordPlain, $using:domainUserName, 'MSSQLSERVER', $using:failoverClusterName, $using:sqlFciIp)
                        Start-Process -FilePath $sqlServerInstaller -ArgumentList $sqlServerInstallationArgumentsString -PassThru -Wait

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'End fci configuration';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }
                    }
                    PsDscRunAsCredential = $domainCredential
                    DependsOn  = '[WaitForCluster]WaitForCluster', '[WaitForAll]WaitFciFirstNodeSetup'
                }
            }

            if ($dscBlocks.RestoreSampleDatabase -band $deploymentMask) {
                # WaitForRemote
                WaitForAll 'WaitSampleDatabaseBackup' {
                    ResourceName         = '[Script]CreateSampleDatabase'
                    NodeName             = $node1
                    RetryIntervalSec     = 10
                    RetryCount           = 30
                    PsDscRunAsCredential = $domainCredential
                    DependsOn            = '[SqlSetup]InstallDefaultInstance'
                }
                # Restore sample database
                Script 'RestoreSampleDatabase' {
                    GetScript = {
                        $db =  Get-SqlDatabase -ServerInstance $using:dnnName | Where-Object {$_.Name.StartsWith($using:databaseName)}
                        if ($db -ne $null) {
                            $result = 'Present';
                        }
                        else {
                            $result = 'Absent';
                        }
                        return @{Ensure = $result };
                    }
                    TestScript = {
                        $state = [scriptblock]::Create($GetScript).Invoke();
                        return $state.Ensure -eq 'Present';
                    }
                    SetScript = {

                        New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                            deployment_name = $using:deploymentName
                            state = 'Begin sample database restore';
                            time = (Get-Date).ToString();
                            instance_name = $using:ComputerName;
                        }

                        $sqlStatement = [string]::Format("
                            -- Create a backup
                            RESTORE DATABASE [bookshelf] FROM DISK = '\\{0}\Backup\bookshelf.bak' WITH NORECOVERY
                            GO
                            ALTER DATABASE [bookshelf] SET HADR AVAILABILITY GROUP = [{1}]
                            GO", $using:witnessName, $using:agName)
                            Invoke-Sqlcmd -query $sqlStatement -TrustServerCertificate

                            New-GcLogEntry -LogName 'Ansible_logs' -JsonPayload @{
                                deployment_name = $using:deploymentName
                                state = 'End sample database restore';
                                time = (Get-Date).ToString();
                                instance_name = $using:ComputerName;
                            }
                    }
                    DependsOn            = '[WaitForAll]WaitSampleDatabaseBackup'
                    PsDscRunAsCredential = $domainCredential
                }
            }
        }
        if ($dscBlocks.AddSysAdminAccount -band $deploymentMask -and
            # For HA deployment, only add users to first node
            ($deploymentMask -eq 1 -or $Parameters.isFirst)
        ) {

            $dependsOn = '[SqlSetup]InstallDefaultInstance'
            if ($deploymentMask -eq 4) {
                # For S2D deployment, use '[Script]SqlServerSetup'
                if ($Parameters.isFirst) {
                    $dependsOn = '[SqlSetup]FciFirstNodeSetup'
                }
                else {
                    $dependsOn = '[Script]SqlServerSetup'
                }
            }

            SqlLogin 'AddWindowsUser' {
                Ensure               = 'Present'
                Name                 = $domainSLD + '\' + $Parameters.adUsername
                LoginType            = 'WindowsUser'
                ServerName           = $Node.NodeName
                InstanceName         = 'MSSQLSERVER'
                DependsOn            = $dependsOn
            }

            SqlRole Add_ServerRole_sysadmin {
                Ensure               = 'Present'
                ServerRoleName       = 'sysadmin'
                MembersToInclude     = $domainSLD + '\' + $Parameters.adUsername
                ServerName           = $Node.NodeName
                InstanceName         = 'MSSQLSERVER'
                DependsOn = '[SqlLogin]AddWindowsUser'
            }

            SqlLogin 'AddSqlSaAccount' {
                Name                    = 'sa'
                InstanceName            = 'MSSQLSERVER'
                Ensure                  = 'Present'
                LoginCredential         = $sqlCredential
                LoginMustChangePassword = $false
                LoginType               = 'SqlLogin'
                Disabled                = $false
                DependsOn               = $dependsOn
              }
        }

        if ($dscBlocks.AddDscRegistryKey -band $deploymentMask) {
            $dependsOn = '[Script]MoveDatabaseFiles'
            if ($deploymentMask -eq 2) {
                if ($Parameters.isFirst) {
                    $dependsOn = '[ADObjectPermissionEntry]AddDNNPermission'
                }
                else {
                    $dependsOn = '[SqlAGReplica]AddReplica'
                }
            }
            if ($deploymentMask -eq 4) {
                if ($Parameters.isFirst) {
                    $dependsOn = '[Script]SetupDNNFCI'
                }
                else {
                    $dependsOn = '[Script]SqlServerSetup'
                }
            }

            Registry 'AddDscRegistryKey' {
                Ensure = 'Present'
                Key = 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Google\WorkloadManager\SQLServerDeployment'
                ValueName = 'InitialConfiguration'
                ValueData = 1
                ValueType = 'Binary'
                DependsOn = $dependsOn
            }
        }
    }
}