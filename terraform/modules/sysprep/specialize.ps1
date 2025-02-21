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

Set-StrictMode -Version Latest;

$ErrorActionPreference  = 'Stop';
$VerbosePreference      = 'SilentlyContinue';
$DebugPreference        = 'SilentlyContinue';

$nameHost = '${nameHost}';
$adSecretName = '${adSecretName}';
$sqlSecretName = '${sqlSecretName}'
$parametersConfiguration = ConvertFrom-Json -InputObject '${parametersConfiguration}';
$pathTemp = "$($env:SystemDrive)\Windows\Temp";

try {
  # Fix issues with downloading from GitHub due to deprecation of TLS 1.0 and 1.1
  # https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/405#issuecomment-379932793
  New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Force | Out-Null;
  New-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Force | Out-Null;

  # Install required PowerShell modules
  # Using PowerShellGet in specialize does not work as PSGallery PackageSource can't be registered
  $modules = @(
      @{
          Name = 'xPSDesiredStateConfiguration'
          Version = '9.1.0'
      },
      @{
          Name = 'NetworkingDsc'
          Version = '8.2.0'
      },
      @{
          Name = 'ComputerManagementDsc'
          Version = '8.4.0'
      },
      @{
          Name = 'ActiveDirectoryDsc'
          Version = '6.2.0'
      },
      @{
          Name = 'SqlServer'
          Version = '22.2.0'
      },
      @{
          Name = 'GoogleCloud'
          Version = ' 2.8.5'
      }
  );

  if ([bool]$parametersConfiguration.PSObject.Properties['modulesDsc']) {
      foreach($module in $parametersConfiguration.modulesDsc) {
          $modules += $module;
      }
  }

  $pathPsBase = 'C:\Program Files\WindowsPowerShell';
  foreach($module in $modules) {
      $pathPsModuleZip = Join-Path -Path $pathPsBase -ChildPath "$($module.Name).zip";
      $pathPsModuleStaging = Join-Path -Path $pathPsBase -ChildPath "ModulesStaging\$($module.Name)-$($module.Version)";
      $pathPsModule = Join-Path -Path $pathPsBase -ChildPath "Modules\$($module.Name)";

      if (-not (Test-Path -Path $pathPsModule)) {
          New-Item -Type Directory -Path $pathPsModule | Out-Null;
          Invoke-WebRequest -Uri "https://www.powershellgallery.com/api/v2/package/$($module.Name)/$($module.Version)" -OutFile $pathPsModuleZip;
          Expand-Archive -Path $pathPsModuleZip -DestinationPath $pathPsModuleStaging;

          # Cleanup nupkg files
          $files = @(
              '[Content_Types].xml',
              '*.nuspec',
              '_rels'
          );

          foreach($file in $files) {
              $pathDeletion = Join-Path -Path $pathPsModuleStaging -ChildPath $file;
              if (Test-Path -Path $pathDeletion) {
                  Remove-Item -Path $pathDeletion -Recurse;
              }
          }

          Move-Item -Path $pathPsModuleStaging -Destination (Join-Path -Path $pathPsModule -ChildPath $module.Version);
      }
  }

  $project = $parametersConfiguration.projectId;

  # function to add logs to google cloud logging
  function AddTo-LogFile {
    param (
      [hashtable] $logData
    )

  New-GcLogEntry -LogName 'Ansible_logs' `
                -JsonPayload $logData
  }

  function Log-PsStart {
    $time = (Get-Date).ToString()
    $message = @{
      baseDir = $PSCommandPath;
      deployment_name = $parametersConfiguration.deploymentName;
      state = 'ps start';
      time = $time;
    }
    AddTo-LogFile -logData $message
  }

  function Log-DscStart {
    param
    (
      [string] $Result
    )
    $time = (Get-Date).ToString()
    $message = @{
      baseDir = $PSCommandPath;
      deployment_name = $parametersConfiguration.deploymentName;
      state = 'dsc start';
      time = $time;
    }
    AddTo-LogFile -logData $message
  }

  function Log-PsEnd {
    $time = (Get-Date).ToString()
    $message = @{
      baseDir = $PSCommandPath;
      deployment_name = $parametersConfiguration.deploymentName;
      state = 'ps end';
      result = (Get-DscConfigurationStatus).Status;
      time = $time;
    }
    AddTo-LogFile -logData $message
  }

  Log-PsStart

  # Create certificate to encrypt mof
  $pathDscCertificate = (Join-Path -Path $pathTemp -ChildPath 'dsc.cer');
  if (-not (Test-Path -Path $pathDscCertificate)) {
      $certificate = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'DscEncryptionCertificate' -HashAlgorithm SHA256;
      Export-Certificate -Cert $certificate -FilePath $pathDscCertificate -Force | Out-Null;
  }
  else {
      $certificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq 'CN=DscEncryptionCertificate'};
  }

  $pathDscMetaDefinition = (Join-Path -Path $pathTemp -ChildPath 'meta.ps1');
  $pathDscConfigurationDefinition = (Join-Path -Path $pathTemp -ChildPath 'configuration.ps1');

  $inlineMeta = $parametersConfiguration.inlineMeta;
  $inlineConfiguration = $parametersConfiguration.inlineConfiguration;

  # Only write inlineMeta if file does not exist on disk
  if (-not (Test-Path -Path $pathDscMetaDefinition)) {
      [IO.File]::WriteAllBytes($pathDscMetaDefinition, [Convert]::FromBase64String($inlineMeta));
  }

  # Customization is optional
  $inlineConfigurationCustomization = $null;
  if ('inlineConfigurationCustomization' -in $parametersConfiguration.PSObject.Properties.Name) {
      $inlineConfigurationCustomization = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parametersConfiguration.inlineConfigurationCustomization));
  }

  # Only write inlineConfiguration if file does not exist on disk
  if (-not (Test-Path -Path $pathDscConfigurationDefinition)) {
      $content = "";

      if (-not [string]::IsNullOrEmpty($inlineConfigurationCustomization)) {
          # Customization is present write first
          $content = $inlineConfigurationCustomization;
      }
      else {
          # Set empty customization if not present
          $content = 'Configuration Customization {}';
      }

      $content += "`n`n$([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($inlineConfiguration)))";
      Set-Content -Path $pathDscConfigurationDefinition -Value $content;
  }

  # Source DSC (meta) configuration
  . $pathDscMetaDefinition;
  . $pathDscConfigurationDefinition;

  # Build DSC (meta) configuration
  $pathDscConfigurationOutput = Join-Path -Path $pathTemp -ChildPath 'dsc';

  ConfigurationMeta `
      -ComputerName 'localhost' `
      -Thumbprint $certificate.Thumbprint `
      -OutputPath $pathDscConfigurationOutput | Out-Null;

  $parametersConfiguration| Out-File 'C:\Windows\Temp\inputs.json'
  Log-DscStart
  # Execute ConfigurationWorkload
  ConfigurationWorkload `
      -ComputerName $nameHost `
      -SQLSecretName $sqlSecretName `
      -ADSecretName $adSecretName `
      -Parameters $parametersConfiguration `
      -ConfigurationData @{AllNodes = @(@{NodeName = $nameHost; PSDscAllowDomainUser = $true; CertificateFile = $pathDscCertificate; Thumbprint = $certificate.Thumbprint})} `
      -OutputPath $pathDscConfigurationOutput | Out-Null;

  # Enact meta configuration
  Set-DscLocalConfigurationManager -Path $pathDscConfigurationOutput -ComputerName 'localhost';

  # Make DSC configuration pending
  $pathDscConfigurationPending = Join-Path -Path 'C:\Windows\system32\Configuration' -ChildPath 'pending.mof';
  Move-Item -Path (Join-Path -Path $pathDscConfigurationOutput -ChildPath "$($nameHost).mof") -Destination $pathDscConfigurationPending;

  # Enact DSC configuration for debugging/testing purposes
  # Start-DscConfiguration -Path $pathDscConfigurationOutput -Wait -Force -Verbose;
  Log-PsEnd
} catch {
    $exception = $_.Exception.Message;
    $message = @{
        baseDir = $PSCommandPath;
        deployment_name = $parametersConfiguration.deploymentName;
        state = 'playbook_end';
        playbook_stats = @{
            'failures' = @{
                $nameHost = $_.Exception.Message
            };
        };
        time = (Get-Date).ToString();
    }
    if ($exception -like '*The Consistency Check or Pull cmdlet is in progress*') {
        $message.playbook_stats.failures = @{}
    }
    New-GcLogEntry -LogName 'Ansible_logs' `
                -JsonPayload $message

    throw
}