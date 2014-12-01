. "C:\cloud-automation\secrets.ps1"
Configuration rsPlatform
{  
   param
   (
      [parameter(Mandatory = $true)]
      [ValidateSet("Present","Absent")]
      [System.String]
      $Ensure
   )
   Import-DscResource -ModuleName rsGit
   rsGit rsGit
   {
      name = "rsGit_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsGit.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsNetAdapter
   {
      name = "rsNetAdapter_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsNetAdapter.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsCertificateStore
   {
      name = "rsCertificateStore_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsCertificateStore.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsFileDownload
   {
      name = "rsFileDownload_1.0.1"
      Source = "https://github.com/rsWinAutomationSupport/rsFileDownload.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.1"
      Logging = $false
   }
   rsGit msActiveDirectory
   {
      name = "msActiveDirectory_2.0"
      Source = "https://github.com/rsWinAutomationSupport/msActiveDirectory.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v2.0"
      Logging = $false
   }
   rsGit rsCloudServersOpenStack
   {
      name = "rsCloudServersOpenStack_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsCloudServersOpenStack.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit msDnsServer
   {
      name = "msDnsServer_1.0"
      Source = "https://github.com/rsWinAutomationSupport/msDnsServer.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0"
      Logging = $false
   }
   rsGit msDatabase
   {
      name = "msDatabase_1.1"
      Source = "https://github.com/rsWinAutomationSupport/msDatabase.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.1"
      Logging = $false
   }
   rsGit rsFTPAdministration
   {
      name = "rsFTPAdministration_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsFTPAdministration.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsCloudLoadBalancers
   {
      name = "rsCloudLoadBalancers_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsCloudLoadBalancers.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsScheduledTask
   {
      name = "rsScheduledTask_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsScheduledTask.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsRaxMon
   {
      name = "rsRaxMon_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsRaxMon.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsSMTP
   {
      name = "rsSMTP_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsSMTP.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsWPI
   {
      name = "rsWPI_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsWPI.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit msPhp
   {
      name = "msPhp_1.0.1"
      Source = "https://github.com/rsWinAutomationSupport/msPhp.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.1"
      Logging = $false
   }
   rsGit msMySql
   {
      name = "msMySql_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/msMySql.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit msJea
   {
      name = "msJea_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/msJea.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit msSmbShare
   {
      name = "msSmbShare_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/msSmbShare.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit msNetworking
   {
      name = "msNetworking_2.1"
      Source = "https://github.com/rsWinAutomationSupport/msNetworking.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules\"
      Ensure = $Ensure
      Branch = "v2.1"
      Logging = $false
   }
   rsGit msComputerManagementv1
   {
      name = "msComputerManagement_1.2"
      Source = "https://github.com/rsWinAutomationSupport/msComputerManagement.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.2"
      Logging = $false
   }
   rsGit msWebAdministration
   {
      name = "msWebAdministration_1.3.2"
      Source = "https://github.com/rsWinAutomationSupport/msWebAdministration.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.3.2"
      Logging = $false
   }
   rsGit msWinEventLog
   {
      name = "msWinEventLog_0.0.0.1"
      Source = "https://github.com/rsWinAutomationSupport/msWinEventLog.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v0.0.0.1"
      Logging = $false
   }
   rsGit msSystemSecurity
   {
      name = "msSystemSecurity_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/msSystemSecurity.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsPSDesiredStateConfiguration
   {
      name = "rsPSDesiredStateConfiguration_1.1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsPSDesiredStateConfiguration.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.1.0.0"
      Logging = $false
   }
   rsGit msPSDesiredStateConfiguration
   {
      name = "msPSDesiredStateConfiguration_3.0.1.0"
      Source = "https://github.com/rsWinAutomationSupport/msPSDesiredStateConfiguration.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v3.0.1.0"
      Logging = $false
   }
   rsGit rsPullServerMonitor
   {
      name = "rsPullServerMonitor_1.0"
      Source = "https://github.com/rsWinAutomationSupport/rsPullServerMonitor.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0"
      Logging = $false
   }
   rsGit PowerShellAccessControl
   {
      name = "rsPwerShellAccessControl_1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/PowerShellAccessControl.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
   }
   rsGit rsClientMofs
   {
      name = "rsClientMofs_1.2.0"
      Source = "https://github.com/rsWinAutomationSupport/rsClientMofs.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.2.0"
      Logging = $false
   }
   rsGit rsWSMan
   {
      name = "rsWSMan_v.1.0.0"
      Source = "https://github.com/rsWinAutomationSupport/rsWSMan.git"
      Destination = "C:\Program Files\WindowsPowerShell\Modules"
      DestinationZip = "C:\Program Files\WindowsPowerShell\DscService\Modules"
      Ensure = $Ensure
      Branch = "v1.0.0"
      Logging = $false
   }
   rsGit rsProvisioning
   {
      name = "rsProvisioning_v.1.1.0"
      Source = "https://github.com/rsWinAutomationSupport/rsProvisioning.git"
      Destination = $($d.wD)
      Ensure = $Ensure
      Branch = "v1.1.0"
      Logging = $false
   }
}
       