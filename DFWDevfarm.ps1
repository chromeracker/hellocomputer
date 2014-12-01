#This is script is used to prepare the test client server to install IIS and Inetmgr
#This script is built into the automation workflow
param ([string]$Node, [string]$ObjectGuid, [string]$MonitoringID, [string]$MonitoringToken)

. "C:\cloud-automation\secrets.ps1"

Configuration Nodes
{
   Import-DSCResource -ModuleName rsScheduledTask
   Import-DSCResource -ModuleName rsGit
   Import-DSCResource -ModuleName msWebAdministration
   Import-DSCResource -ModuleName rsNetAdapter
   Import-DSCResource -ModuleName rsCertificateStore
   Import-DSCResource -ModuleName rsWSMan
   
   Node $Node
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
      WindowsFeature IIS
      {
         Ensure = "Present"
         Name = "Web-Server"
      }
      WindowsFeature WebManagement
      {
         Ensure = "Present"
         Name = "Web-Mgmt-Tools"
      }
      WindowsFeature AspNet45
      {
         Ensure          = "Present"
         Name            = "Web-Asp-Net45"
      }
      rsGit rsConfigs
      {
         Name            = "rsConfigs"
         Ensure          = "Present"
         Source          =  $(("git@github.com:", $($d.gCA) -join ''),  $($($d.mR), ".git" -join '') -join '/')
         Destination     = $($d.wD)
         Branch          = "master"
      }
      rsGit rsProvisioning
      {
         Name            = "rsProvisioning"
         Ensure          = "Present"
         Source          = $("https://github.com", $($d.gMO) , $($($d.prov), ".git" -join '' ) -join '/')
         Destination     = $($d.wD)
         Branch          = "master"
      }
      xWebsite DefaultSite 
      {
         Ensure          = "Present"
         Name            = "Default Web Site"
         State           = "Stopped"
         PhysicalPath    = "C:\inetpub\wwwroot"
         DependsOn       = "[WindowsFeature]IIS"
      }
   <#
      xWebAppPool WinDevOpsAppPool
      { 
         Name   = "WinDevOps" 
         Ensure = "Present" 
         State  = "Started" 
      }
      rsGit WebSites
      {
         Name            = "WebSites"
         Ensure          = "Present"
         Source          = "git@github.com:<customergithubaccount>/WebSites.git"
         Destination     = "D:\"  
         Branch          = "master"
      }
      
      xWebSite WinDevOps
      { 
         Name   = "WinDevOps" 
         Ensure = "Present" 
         ApplicationPool = "WinDevOps"
         BindingInfo = MSFT_xWebBindingInformation 
         { 
            Port = 80
            Protocol = "HTTP"
            HostName = "WinDevOps.local"
         }
         PhysicalPath = "D:\WebSites\WinDevOps"
         State = "Started" 
         DependsOn = @("[xWebAppPool]WinDevOpsAppPool","[rsGit]WebSites") 
      } 
      #>
      rsCertificateStore MYWSManCert
      {
        Ensure = "Present"
        Name = "MYWSManCert"
        Path = $($d.wD, $d.mR, "Certificates\WSMan.pfx" -join '\')
        Location = "LocalMachine"
        Store = "MY"
        Password = $($d.gAPI)
      }
      rsCertificateStore RootWSManCert
      {
        Ensure = "Present"
        Name = "RootWSManCert"
        Path = $($d.wD, $d.mR, "Certificates\WSMan.pfx" -join '\')
        Location = "LocalMachine"
        Store = "Root"
        Password = $($d.gAPI)
      }
      rsWSManConfig WSMan
      {
        Name = "WSMan"
        CertThumbprint = $((Get-PfxCertificate -FilePath $($d.wD,$d.mR,"Certificates\WSMan.crt" -join'\')).Thumbprint)
        Ensure = "Present"
        Username = "WSManCertAdmin"
      }
      rsScheduledTask VerifyTask
      {
         ExecutablePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
         Params = $($d.wD, $d.prov, "Verify.ps1" -join '\')
         Name = "Verify"
         IntervalModifier = "Minute"
         Ensure = "Present"
         Interval = "5"
      } 
      
   }
}
$fileName = [System.String]::Concat($ObjectGuid, ".mof")
$mofFile = Nodes -Node $Node -ObjectGuid $ObjectGuid -OutputPath 'C:\Program Files\WindowsPowerShell\DscService\Configuration\'
$newFile = Rename-Item -Path $mofFile.FullName -NewName $fileName -PassThru
New-DSCCheckSum -ConfigurationPath $newFile.FullName -OutPath 'C:\Program Files\WindowsPowerShell\DscService\Configuration\'