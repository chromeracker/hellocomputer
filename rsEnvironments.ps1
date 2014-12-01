##################################################################################################################################
##################################################################################################################################
#This script configures the Pull server
#This script is called by baseprep.ps1 during the automated workflow and continues to run with Verify Task
##################################################################################################################################
##################################################################################################################################



##################################################################################################################################
# Import RS Cloud and Github account information.
##################################################################################################################################
. "C:\cloud-automation\secrets.ps1"
. "$($d.wD, $d.mR, "PullServerInfo.ps1" -join '\')"

##################################################################################################################################
# Begin Configuration
##################################################################################################################################
configuration Assert_DSCService
{
   param
   (
      [string[]]$NodeName,
      [ValidateNotNullOrEmpty()]
      [string] $certificateThumbPrint
   )
   
   
   ##################################################################################################################################
   # Import Required Modules
   ##################################################################################################################################
   Import-DscResource -ModuleName rsCloudServersOpenStack
   Import-DscResource -ModuleName rsCloudLoadBalancers
   Import-DscResource -ModuleName rsScheduledTask
   Import-DscResource -ModuleName msPSDesiredStateConfiguration
   Import-DscResource -ModuleName rsPlatform
   Import-DscResource -ModuleName rsGit
   Import-DscResource -ModuleName rsClientMofs
   Import-DSCResource -ModuleName msWebAdministration
   Import-DSCResource -ModuleName PowerShellAccessControl
   Import-DSCResource -ModuleName rsNetAdapter
   
   Node $NodeName
   {
      ##################################################################################################################################
      # Configures default NIC names to ensure they meet standard naming convention, if the server is Rackconnect v2 the Name value
      # will be overridden to unused and private and the unused interface will be disabled
      ##################################################################################################################################
      rsNetAdapter SetDefaultNic0
      {
         InterfaceDescription = "Citrix PV Network Adapter #0"
         Name = "Public"
      }
      rsNetAdapter SetDefaultNic1
      {
         InterfaceDescription = "Citrix PV Network Adapter #1"
         Name = "Private"
      }
      ##################################################################################################################################
      # Install Required Windows Features (pull server)
      ##################################################################################################################################
      WindowsFeature IIS
      {
         Ensure = "Present"
         Name = "Web-Server"
      }
      
      WindowsFeature InetMgr
      {
         Ensure = "Present"
         Name = "Web-Mgmt-Tools"
      }
      
      WindowsFeature DSCServiceFeature
      {
         Ensure = "Present"
         Name = "DSC-Service"
      }
      
      
      ##################################################################################################################################
      # Install DSC Webservices
      ##################################################################################################################################
      
      xDscWebService PSDSCPullServer
      {
         Ensure = "Present"
         EndpointName = "PSDSCPullServer"
         Port = 8080
         PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
         CertificateThumbPrint = $certificateThumbPrint
         ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
         ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
         State = "Started"
         DependsOn = "[WindowsFeature]DSCServiceFeature"
      }
      
      xDscWebService PSDSCComplianceServer
      {
         Ensure = "Present"
         EndpointName = "PSDSCComplianceServer"
         Port = 9080
         PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
         CertificateThumbPrint = $certificateThumbPrint
         State = "Started"
         IsComplianceServer = $true
         DependsOn = @("[WindowsFeature]DSCServiceFeature","[xDSCWebService]PSDSCPullServer")
      }
      
      
      ##################################################################################################################################
      # Pull Down Modules that are setup in rsPlatform
      ##################################################################################################################################
      
      rsGit rsConfigs
      {
         name = "rsConfigs"
         Source = (("git@github.com:", $($d.gCA) -join ''), $($($d.mR), ".git" -join '') -join '/')
         Destination = $($d.wD)
         Ensure = "Present"
         Branch = "master"
         Logging = $false
      }
      
      File rsPlatformDir
      {
         SourcePath = $($d.wD, $d.mR, "rsPlatform" -join '\')
         DestinationPath = "C:\Program Files\WindowsPowerShell\Modules\rsPlatform"
         Type = "Directory"
         Recurse = $true
         Ensure = "Present"
      }
      
      rsPlatform Modules
      {
         Ensure = "Present"
      }
      ##################################################################################################################################
      # Setting known hosts file using a hashtable
      ##################################################################################################################################
      $sshPaths = @{"git" = "C:\Program Files (x86)\Git\.ssh"; "sys32" = "C:\Windows\System32\config\systemprofile\.ssh"; "administrator" = "C:\Users\Administrator\.ssh"; "syswow" = "C:\Windows\SysWOW64\config\systemprofile\.ssh"}
      foreach ($sshPath in $sshPaths.keys) {
         rsSSHKnownHosts $sshPath
         {
            path = $($sshPaths.$($sshPath))
            gitIps = @("github.com,192.30.252.129", "192.30.252.128", "192.30.252.130", "192.30.252.131")
            gitRsa = "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
         }
      }
      ##################################################################################################################################
      # Define server and loadbalancer environments (Orchestration Layer)
      ##################################################################################################################################
      
      ### Environment section commented out for template, please edit this section for your own environment builds
      
<#
      rsCloudServersOpenStack DFWwebfarm
      {
        Ensure = "Present"
        minNumberOfDevices = 1
        maxNumberOfDevices = 9
        namingConvention = "Farm"
        image = "Windows Server 2012"
        nflavor = "performance1-4"
        dataCenter = "DFW"
        role = "webFarm"
        pullServerName = "PULLServer"
        environmentGuid = "UNIQUEGUID"
        BuildTimeOut = 30
        EnvironmentName = "DFWwebfarm"
      }


      rsCloudServersOpenStack DFWDevfarm
      {
        Ensure = "Absent"
        minNumberOfDevices = 1
        maxNumberOfDevices = 9
        namingConvention = "DevFarm"
        image = "Windows Server 2012"
        nflavor = "performance1-4"
        dataCenter = "DFW"
        role = "webFarm"
        pullServerName = "PULLServer"
        environmentGuid = "UNIQUEGUID"
        BuildTimeOut = 30
        EnvironmentName = "DFWDevfarm"
      }


      rsCloudLoadBalancers prod_dfwlb
      {
        loadBalancerName = "dfwlb"
        port = 80
        protocol = "HTTP"
        nodes = @("ENVIRONMENTGUIDTOBEUSED")
        dataCenter = "DFW"
        attemptsBeforeDeactivation = 3
        delay = 10
        path = "/"
        hostHeader = "windevops.local"
        statusRegex = "^[234][0-9][0-9]$"
        timeout = 10
        type = "HTTP"
        algorithm = "ROUND_ROBIN"
      }
#>      
      
      ##################################################################################################################################
      # Add Github SSH keys to known hosts and add pull server SSH key to github account - Add Github webhook
      ##################################################################################################################################
      rsClientMofs CheckMofs
      {
         Name = "CheckMofs"
         Ensure = "Present"
         Logging = $true
      }
   
      rsGitSSHKey pullserver_sshkey
      {
         installedPath = "C:\Program Files (x86)\Git\.ssh"
         hostedPath = $(($d.wD), $($d.mR), "Certificates" -join '\') 
         logging = $false
      }
      xWebsite DefaultSite 
      {
         Ensure          = "Absent"
         Name            = "Default Web Site"
         State           = "Stopped"
         PhysicalPath    = "C:\inetpub\wwwroot"
         DependsOn       = "[WindowsFeature]IIS"
      }
      rsGit Arnie
      {
         name = "Arnie"
         Source = "https://github.com/rsWinAutomationSupport/Arnie.git"
         Destination = "C:\inetpub\wwwroot"
         Ensure = "Present"
         Branch = "master"
      }
      xWebAppPool GitWebHook {
         Ensure = "Present"
         Name = "GitWebHook"
      }
      xWebSite GitWebHook
      {
         Name = "GitWebHook"
         ApplicationPool = "GitWebHook"
         Ensure = "Present"
         State = "Started"
         PhysicalPath = "C:\inetpub\wwwroot\Arnie\Arnie\"
         BindingInfo = @(
              @(MSFT_xWebBindingInformation
              {
                  IPAddress = "*"
                  Port = 80
                  Protocol = "HTTP"
              });
          )
         DependsOn = @("[xWebAppPool]GitWebHook","[xWebsite]DefaultSite")
      }
      Script changeAllowedIPs {
         GetScript = { return @{"allowedAddresses"="192.168.*.*,127.0.0.1,::1,192.30.252.*"}}
         SetScript = {
            [xml]$webConfig = Get-Content "C:\inetpub\wwwroot\Arnie\Arnie\web.config"
            $webConfig.configuration.arnieConfig.allowedAddresses = "192.168.*.*,127.0.0.1,::1,192.30.252.*"
            $webConfig.Save("C:\inetpub\wwwroot\Arnie\Arnie\web.config")
         }
         TestScript = {
            [xml]$webConfig = Get-Content "C:\inetpub\wwwroot\Arnie\Arnie\web.config"
            if( $webConfig.configuration.arnieConfig.allowedAddresses -eq "192.168.*.*,127.0.0.1,::1,192.30.252.*" )
            {return $true} 
            else {return $false}
         }
         DependsOn = "[rsGit]Arnie"
      }
      File GitWebHookAction
      {
         SourcePath = $($d.wD, $d.mR, "Configuration.json" -join '\')
         DestinationPath = "C:\inetpub\wwwroot\Arnie\Arnie\App_Data\Configuration.json"
         Ensure = "Present"
      }
      rsWebHook DDI_rsConfigs
      {
         Name = "DDI_rsConfigs"
         Repo = "$($d.mR)"
         PayloadURL = $( "http://",$($pullserverInfo.pullserverPublicIp),"/Arnie.svc/DoItNow" -join'' )
         Ensure = "Present"
         Logging = $true
         DependsOn = "[cAccessControlEntry]ReadExecuteVerify"
      }
      
      ##################################################################################################################################
      # Create scheduled task to verify config
      ##################################################################################################################################
      rsScheduledTask VerifyTask
      {
         ExecutablePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
         Params = $($d.wD, $d.prov, "Verify.ps1" -join '\')
         Name = "Verify"
         IntervalModifier = "Minute"
         Ensure = "Present"
         Interval = "30"
      }
      
      cAccessControlEntry ReadExecuteVerify
      {
         Ensure = "Present"
         Path = "C:\Windows\System32\Tasks\Verify"
         AceType = "AccessAllowed"
         ObjectType = "File"
         AccessMask = ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
         Principal = "IIS AppPool\GitWebHook"
         DependsOn = @("[rsScheduledTask]VerifyTask","[xWebAppPool]GitWebHook")
      }
   }
   
}
##################################################################################################################################
# Configuration end - lines below run the config and create/install cert used for client/pull HTTPS comms
##################################################################################################################################
taskkill /F /IM WmiPrvSE.exe
$NodeName = $env:COMPUTERNAME
$cN = "CN=" + $NodeName
Remove-Item -Path "C:\Windows\Temp\Assert_DSCService" -Force -Recurse -ErrorAction SilentlyContinue
if(!( (Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq $cN}) -and (Get-ChildItem Cert:\LocalMachine\Root\ | where {$_.Subject -eq $cN}) -and (Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq 'CN=WSMan'})) ) {
   Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq $cN} | Remove-Item
   Get-ChildItem Cert:\LocalMachine\Root\ | where {$_.Subject -eq $cN} | Remove-Item
   Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq 'CN=WSMan'} | Remove-Item
   if( !(Test-Path -Path $($d.wD, $d.mR, "Certificates" -join '\')) ) {
      New-Item -Path $($d.wD, $d.mR, "Certificates" -join '\') -ItemType directory
   }
   if( !(Test-Path $($d.wD, $d.mR, "Certificates\PullServer.crt" -join '\')) ) {
      Remove-Item -Path $($d.wD, $d.mR, "Certificates\PullServer.crt" -join '\') -Force
   }
   if( !($($d.wD, $d.mR, "Certificates\WSMan.crt" -join '\')) ) {
      Remove-Item -Path $($d.wD, $d.mR, "Certificates\WSMan.crt" -join '\') -Force
   }   
   if( !(Test-Path $($d.wD, $d.mR, "Certificates\WSMan.pfx" -join '\')) ) {
      Remove-Item -Path $($d.wD, $d.mR, "Certificates\WSMan.pfx" -join '\') -Force
   }
   powershell.exe $($d.wD, $d.prov, "makecert.exe" -join '\') -r -pe -n $cN, -ss my $($d.wD, $d.mR, "Certificates\PullServer.crt" -join '\'), -sr localmachine, -len 2048
   Start -Wait $($d.wD, $d.prov, "makecert.exe" -join '\') -ArgumentList "-r -pe -n ""CN=WSMan"" -ss my ""$($d.wD, $d.mR, "Certificates\WSMan.crt" -join '\')"" -sr localmachine -a sha1 -len 2048 -eku 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"
   powershell.exe certutil -addstore -f Root, ""$($d.wD, $d.mR, "Certificates\WSMan.crt" -join '\')""
   (Get-ChildItem Cert:\LocalMachine\My | ? Subject -eq 'CN=WSMan') | Export-PfxCertificate -FilePath $($d.wD, $d.mR, "Certificates\WSMan.pfx" -join '\') -Password (ConvertTo-SecureString $($d.gAPI) -AsPlainText –Force )
   chdir $($d.wD, $d.mR -join '\')
   Start-Service Browser
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD, $d.mR, "Certificates\PullServer.crt" -join '\')"
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD, $d.mR, "Certificates\WSMan.crt" -join '\')"
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD, $d.mR, "Certificates\WSMan.pfx" -join '\')"
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -a -m `"pushing PullServer.crt and WSMan Certs`""
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.br)"
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.br)"
   Stop-Service Browser
   powershell.exe certutil -addstore -f my $($d.wD, $d.mR, "Certificates\PullServer.crt" -join '\')
   powershell.exe certutil -addstore -f root $($d.wD, $d.mR, "Certificates\PullServer.crt" -join '\')
}
chdir C:\Windows\Temp
Assert_DSCService -NodeName $NodeName -certificateThumbPrint (Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq $cN}).Thumbprint -PSDscAllowPlainTextPassword $true
Start-DscConfiguration -Path Assert_DSCService -Wait -Verbose -Force