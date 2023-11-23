# ====== START OF REQUIRED MANUAL CONFIGURATION ====== 
$skip_config = @()
$check_only = @()
$configurate = $false
$skip_stopped_sites = $true

$MAX_ALLOWED_CONTENT_LENGTH = 30000000
$MAX_URL = 4096
$MAX_QUERY_STRING = 2048
$MAX_CONCURRENT_REQUESTS = 5
$LOGS_DIR = "I:\inetpub\logs\LogFiles"
$CIPHER_SUITE_ORDERED = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
$HSTS_MAX_AGE = 480
# ====== END OF REQUIRED MANUAL CONFIGURATION ======

$Websites = If ($skip_stopped_sites) {Get-Website | Where-Object {$_.State -eq "Started"} | Sort-Object -Property Name} Else {Get-Website | Sort-Object -Property Name}
$global:Score = 0

function Print-Results {
  Param(
  [bool]$passed,
  [bool]$changed,
  [bool]$scored,
  [string]$taskName,
  [string]$info,
  [object]$failMsg
  )
  If ($passed) {
      Write-Host "Correct configuration: $($taskName)" -ForegroundColor Green
      If ($scored) {$global:Score++}
  } ElseIf ($changed -and $configurate) {
      Write-Host "Found Error in configuration: $($taskName)" -ForegroundColor Yellow
      Write-Host "Invalid entries:" -ForegroundColor Yellow
      $failMsg
      Write-Host "Changing...`n" -ForegroundColor Yellow
  } Else {
      Write-Host "Found Error in configuration: $($taskName)" -ForegroundColor Red
      Write-Host "Invalid entries:" -ForegroundColor Red
      $failMsg
      Write-Host ""
  }
  If (![string]::IsNullOrEmpty($info)) {Write-Host "$($info)`n" -ForegroundColor Cyan}
}

if (($check_only.count -eq 0) -or ($check_only.contains(1))) {

$task = '1.1 (L1) Ensure web content is on non-system partition'
$results = ($Websites.PhysicalPath -Match "(%SystemDrive%|$($Env:SystemDrive))\\inetpub")

Print-Results -passed ([string]::IsNullOrEmpty($results) -or ($results -eq $false)) -taskName $task -failMsg ($Websites.PhysicalPath) -scored $true

$task = '1.2 (L1) Ensure host headers are on all sites'
$results = (Get-WebBinding -Port *).bindingInformation -Match ':80:$'
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ((Get-WebBinding -Port *).bindingInformation) -scored $true

$task = '1.3 (L1) Ensure directory browsing is set to disabled'
$results = Get-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis:\ -Name Enabled | select -ExpandProperty Value
if (!$results -and $configurate -and !$skip_config.contains(1.3)) {
    Set-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis:\ -Name Enabled -Value False
}
Print-Results -passed (!$results) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(1.3)) -scored $true

$task = '1.4 (L1) Ensure application pool identity is configured for all application pools'
$results = Get-ChildItem 'IIS:\AppPools' | Foreach-Object {
$processModels = Get-ItemProperty "IIS:\AppPools\$($_.Name)" | Select-Object -ExpandProperty 'processModel'
  If ($processModels.identityType -notmatch '(ApplicationPoolIdentity|SpecificUser)') {
      $_.Name + " " + $processModels.identityType + "`n"
      if ($configurate -and !$skip_config.contains(1.4)) {
        Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name "ProcessModel" -Value @{'identityType'='ApplicationPoolIdentity'}
      }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(1.4)) -scored $true

$task = '1.5 (L1) Ensure unique application pools is set for sites'
$results = $Websites | Select-Object Name, applicationPool
$condition = ($results | Sort-Object applicationPool -Unique | Measure).Count -eq ($results | Measure).Count
Print-Results -passed ($condition) -taskName $task -failMsg ($results) -scored $true

$task = '1.6 (L1) Ensure application pool identity is configured for anonymous user identity'
$results = Get-ChildItem 'IIS:\Sites' | Foreach-Object {
  $anonAuth = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -PSPath "IIS:\Sites\$($_.Name)" -Name "userName")
  if($anonAuth.Value -ne '') {
    $anonAuth
    if ($configurate -and !$skip_config.contains(1.6)) {
      Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -PSPath "IIS:\Sites" -Name "userName" -Value ''
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(1.6)) -scored $true

$task = '1.7 (L1) Ensure WebDav feature is disabled (Scored)'
$results = (Get-WindowsFeature Web-DAV-Publishing).InstallState
if ($results -and $configurate -and !$skip_config.contains(1.7)) {
    Remove-WindowsFeature Web-DAV-Publishing
}
Print-Results -passed (!$results) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(1.7)) -scored $true

Write-Output ''
}

if (($check_only.count -eq 0) -or ($check_only.contains(2))) {

$task = "2.1 (L1) Ensure 'global authorization rule' is set to restrict access (Not Scored)"
$info = $null
$add = (Get-WebConfiguration -pspath 'IIS:\' -filter 'system.webServer/security/authorization').GetCollection() | Where-Object {$_.ElementTagName -eq "add"}
$results = $add | ForEach-Object { 
    If (($_.Attributes["users"].Value -eq '*') -and ($_.Attributes["roles"].Value -eq '') -and ($_.Attributes["verbs"].Value -eq '')) {
        "Your configuration allow all users access."
        'Check your configuration for <add accessType="Allow" users="*" /> or similar'
        'You can use this command in cmd: %systemroot%\system32\inetsrv\appcmd list config -section:system.webserver/security/authorization'
        'To fix this please refer to the CIS benchmark or use automatic configuration option'
    }
}
if(!([string]::IsNullOrEmpty($results)) -and $configurate -and !$skip_config.contains(2.1)) {
    try {
        Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "system.webServer/security/authorization" -name "." -AtElement @{users='*';roles='';verbs=''}
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "system.webServer/security/authorization" -name "." -value @{accessType='Allow';roles='Administrators'}
    } catch [System.Runtime.InteropServices.COMException] {
        $info = "Skipped adding @{accessType='Allow';roles='Administrators'} as it already exist"
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(2.1)) -info $info

$task = '2.2 (L1) Ensure access to sensitive site features is restricted to authenticated principals only (Not Scored)'
$results = $Websites | Foreach-Object {
  $config = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $_.Name -filter 'system.webServer/security/authentication/*' -name 'enabled' | Where-Object {$_.value -eq $true}
  if(($config -eq $null) -and ((Get-WebConfiguration system.web/authentication "IIS:\sites\$($_.Name)").Mode -notmatch 'Forms' )) {
    "No authentication module enabled for site $($_.Name). You need to set up appropriate authentication manually. To see how to enable it after configuration please refer to the CIS Benchmark paragraph 2.2"
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results)

$form_auth = $Websites | Where {(Get-WebConfiguration system.web/authentication "IIS:\sites\$($_.Name)").Mode -match 'Forms'} 
if ($form_auth -ne $null) {

$task = '2.3 (L1) Ensure forms authentication require SSL (Scored)'
$results = $form_auth | Foreach-Object {
  if((Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms' -name 'requireSSL').Value -ne $true) {
    $_.Name
    if($configurate -and !$skip_config.contains(2.3)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms' -name 'requireSSL' -Value $true
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(2.3)) -scored $true

$task = '2.4 (L2) Ensure forms authentication is set to use cookies (Scored)'
$results = $form_auth | Foreach-Object {
  if((Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms' -name 'cookieless') -ne 'UseCookies') {
    $_.Name
    if($configurate -and !$skip_config.contains(2.4)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(2.4)) -scored $true

$task = '2.5 (L1) Ensure cookie protection mode is configured for forms authentication (Scored)'
$results = $form_auth | Foreach-Object {
  $config = (Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms' -name 'protection')
  if($config -ne 'All') {
    "$($_.Name): $config"
    if($configurate -and !$skip_config.contains(2.5)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(2.5)) -scored $true
} else {
Write-Host "FormsAuthentication is not enabled. Skipping 2.3, 2.4, 2.5, 2.7" -ForegroundColor Cyan
$global:Score += 4
}

$task = '2.6 (L1) Ensure transport layer security for basic authentication is configured (Scored)'
if ((Get-WindowsFeature Web-Basic-Auth).Installed -eq $true){
$results = $Websites | Foreach-Object {
    if( 
    ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $_.Name -filter 'system.webServer/security/authentication/basicAuthentication' -name 'enabled').Value -eq $true) -and
    ((Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.webServer/security/access' -name 'sslFlags') -ne 'Ssl')
    ) {
        $_.Name
        if($configurate -and !$skip_config.contains(2.6)) {
            Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -location "$($_.Name)" -filter 'system.webServer/security/access' -name 'sslFlags' -value 'Ssl'
        }
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(2.6)) -scored $true
} else {
Write-Host "BasicAuthentication is not installed. Skipping 2.6" -ForegroundColor Cyan
$global:Score += 1
}

if ($form_auth -ne $null) {
$task = '2.7 (L1) Ensure passwordFormat is not set to clear (Scored)'
$results = $form_auth | Foreach-Object {
  if((Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat') -ne 'SHA1') {
    $_.Name
    if($configurate -and !$skip_config.contains(2.7)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' -value 'SHA1'
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(2.7)) -scored $true
}

Write-Output ''
}

if (($check_only.count -eq 0) -or ($check_only.contains(3))) {

$task = '3.1 (L1) Ensure deployment method retail is set (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter 'system.web/deployment' -name 'retail'
  if(($query | select -ExpandProperty Value) -eq $false) {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -scored $true

$task = '3.2 (L2) Ensure debug is turned off (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)"-filter "system.web/compilation" -name "debug"
  if(($query | select -ExpandProperty Value) -eq $true) {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
    if($configurate -and !$skip_config.contains(3.2)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/compilation" -name "debug" -value $false
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.2)) -scored $true

$task = '3.3 (L2) Ensure custom error messages are not off (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/customErrors" -name 'mode'
  if(($query) -notmatch '^(On|RemoteOnly)$') {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
    if($configurate -and !$skip_config.contains(3.3)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/customErrors" -name "mode" -value "RemoteOnly"
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.3)) -scored $true

$task = '3.4 (L1) Ensure IIS HTTP detailed errors are hidden from displaying remotely (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.webServer/httpErrors" -name "errorMode"
  if(($query) -notmatch '^(DetailedLocalOnly)$') {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
    if($configurate -and !$skip_config.contains(3.4)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.webServer/httpErrors" -name "errorMode" -value "DetailedLocalOnly"
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.4)) -scored $true

$task = '3.5 (L2) Ensure ASP.NET stack tracing is not enabled (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/trace" -name "enabled"
  if(($query).Value -ne $false) {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
    if($configurate -and !$skip_config.contains(3.5)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/trace" -name "enabled" -value "False"
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.5)) -scored $true

$task = '3.6 (L2) Ensure httpcookie mode is configured for session state (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/sessionState" -name "cookieless"
  if($query -ne 'UseCookies') {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
    if($configurate -and !$skip_config.contains(3.6)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/sessionState" -name "cookieless" -value "UseCookies"
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.6))

$task = '3.7 (L1) Ensure cookies are set with HttpOnly attribute (Scored)'
$results = $Websites | Foreach-Object {
$query = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/httpCookies" -name "httpOnlyCookies"
  if(($query | select -ExpandProperty Value) -ne $true) {
    $_.Name
    ($query | Out-String).Trim()
    "`n"
    if($configurate -and !$skip_config.contains(3.7)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($_.Name)" -filter "system.web/httpCookies" -name "httpOnlyCookies" -value "True"
    }
  }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.7)) -scored $true

$task = '3.8/9 (L1) Ensure MachineKey validation method - .Net 3.5/4.5 is configured (Scored)'
$results = $Websites | Foreach-Object {
  $siteName = $_.Name
  $version = (Get-ItemProperty -Path "IIS:\AppPools\$applicationPool" | Select-Object *).managedRuntimeVersion
  $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($siteName)").Validation
  If ($version -match "^v2" -and $validation -notmatch '^(SHA1|AES)$') {
    "Site: $siteName"
    "Validation: $validation`n"
    if($configurate -and !$skip_config.contains(3.8)) {
      Set-WebConfigurationProperty -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($siteName)" -name Validation -value 'SHA1'
    }
  } elseif ($version -match "^v4" -and $validation -notmatch '^(HMACSHA256|HMACSHA384|HMACSHA512|AES)$') {
    "Site: $siteName"
    "Validation: $validation`n"
    if($configurate -and !$skip_config.contains(3.9)) {
      Set-WebConfigurationProperty -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($siteName)" -name Validation -value 'AES'
    }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $appPool    = $_.applicationPool
          $version    = (Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *).managedRuntimeVersion
          $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($siteName)$($name)").Validation
          If ($version -Like "v2.*" -and $validation -notmatch '^(SHA1|AES)$') {
            "Site: $siteName$name"
            "Validation: $validation`n"
            if($configurate -and !$skip_config.contains(3.8)) {
              Set-WebConfigurationProperty -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($siteName)$($name)" -name Validation -value 'SHA1'
            }
          } elseif ($version -Like "v4.*" -and $validation -notmatch '^(HMACSHA256|HMACSHA384|HMACSHA512|AES)$') {
            "Site: $siteName$name"
            "Validation: $validation`n"
            if($configurate -and !$skip_config.contains(3.9)) {
              Set-WebConfigurationProperty -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($siteName)$($name)" -name Validation -value 'AES'
            }
          }
      }
  }
 }
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.8) -or !$skip_config.contains(3.9)) -scored $true

$task = '3.10 (L1) Ensure global .NET trust level is configured (Scored)'
$results = $Websites | Foreach-Object {
  $siteName = $_.Name
  $trust = Get-WebConfigurationProperty -pspath "IIS:\sites\$($siteName)" -filter "system.web/trust" -name "level" | select -ExpandProperty Value
  If ($trust -notmatch '^(Medium|Low|Minimal)$') {
      "Site: $site.Name"
      "Trust Level: $trust`n"
      if($configurate -and !$skip_config.contains(3.10)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites\$($siteName)" -filter "system.web/trust" -name "level" -value "Medium"
      }
    }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $trust = Get-WebConfigurationProperty -pspath "IIS:\sites\$($siteName)$($name)" -filter "system.web/trust" -name "level" | select -ExpandProperty Value
          If ($trust -notmatch '^(Medium|Low|Minimal)$') {
            "Site: $($site.Name)$name"
            "Trust Level: $trust`n"
            if($configurate -and !$skip_config.contains(3.10)) {
              Set-WebConfigurationProperty -pspath "IIS:\sites\$($siteName)$($name)" -filter "system.web/trust" -name "level" -value "Medium"
            }
          }
      }
  }
 }
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.10)) -scored $true

$task = '3.11 (L2) Ensure X-Powered-By Header is removed (Not Scored)'
$results = $Websites | Foreach-Object {
  $site = $_
  $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$($site.Name)"
  $customHeaders = $config.GetCollection()

  If ($customHeaders) {
      $customHeaders | ForEach-Object {
        if(($_.Attributes | Where-Object Name -EQ 'name').Value -match 'x-powered-by') {
           "Site: $($site.Name)"
           "X-Powered-By Header: present`n"
           if($configurate -and !$skip_config.contains(3.11)) {
             Remove-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webserver/httpProtocol/customHeaders" -name "." -AtElement @{name='X-Powered-By'}
           }
        }
      }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$($site.Name)$($name)"
          $customHeaders = $config.GetCollection()
          If ($customHeaders) {
              $customHeaders | ForEach-Object {
                if(($_.Attributes | Where-Object Name -EQ 'name').Value -match 'x-powered-by') {
                  "Site: $($site.Name)$name"
                  "X-Powered-By Header: present`n"
                  if($configurate -and !$skip_config.contains(3.11)) {
                    Remove-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)$($name)" -filter "system.webserver/httpProtocol/customHeaders" -name "." -AtElement @{name='X-Powered-By'}
                  }
                }
              }
          }
      }
  }
 }
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(3.11))

$task = '3.12 (L2) Ensure Server Header is removed (Not Scored)'
$results1 = $Websites | Foreach-Object {
  $site = $_
  $config = $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$($site.Name)"
  $customHeaders = $config.GetCollection()

  If ($customHeaders) {
      $customHeaders | ForEach-Object {
        if(($_.Attributes | Where-Object Name -EQ name).Value -match 'server') {
           "Site: $($site.Name)"
           "Server Header: present`n"
        }
      }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $config = $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$($site.Name)"
          $customHeaders = $config.GetCollection()
          If ($customHeaders) {
              $customHeaders | ForEach-Object {
                  if(($_.Attributes | Where-Object Name -EQ name).Value -match 'server') {
                      "Site: $($site.Name)$name"
                      "Server Header: present`n"
                      if($configurate -and !$skip_config.contains(3.12)) {
                        Remove-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webserver/httpProtocol/customHeaders" -name "." -AtElement @{name='server'}
                      }
                  }
              }
          }
      }
  }
 }
$results2 = $null
if((get-itemproperty HKLM:\SOFTWARE\Microsoft\InetStp\).setupstring -match 'IIS 10.0') {
if (!(Get-WebConfigurationProperty -pspath machine/webroot/apphost -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader').Value) {
    $results2 = "removeServerHeader in machine/webroot/apphost at system.webserver/security/requestfiltering is not set to True"
    if($configurate -and !$skip_config.contains(3.12)) {
      Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/security/requestFiltering" -name "removeServerHeader" -value "True"
    }
}
} else {
$info = "Your IIS version is below 10, that means the ability to suppress the server header does not exist in your version. To remove it at the server level, you can set the url rewrite manually (see documentation)"
}
Print-Results -passed ([string]::IsNullOrEmpty($results1) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results1+$results2) -changed (!$skip_config.contains(3.12)) -info $info

Write-Output ''
}

if (($check_only.count -eq 0) -or ($check_only.contains(4))) {

$task = '4.1 (L2) Ensure maxAllowedContentLength is configured (Not Scored)'
$results = $Websites | Foreach-Object {
  $site = $_
  $len = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").requestLimits).Attributes | Where-Object Name -EQ 'maxAllowedContentLength').Value
  if($len -ne $MAX_ALLOWED_CONTENT_LENGTH) {
    "Site: $($site.Name)"
    "MaxAllowedContent: $len`n"
    if($configurate -and !$skip_config.contains(4.1)) {
      Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value $MAX_ALLOWED_CONTENT_LENGTH
    }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $len = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)$($name)").requestLimits).Attributes | Where-Object Name -EQ 'maxAllowedContentLength').Value
          if($len -ne $MAX_ALLOWED_CONTENT_LENGTH) {
            "Site: $($site.Name)$name"
            "MaxAllowedContent: $len`n"
            if($configurate -and !$skip_config.contains(4.1)) {
              Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value $MAX_ALLOWED_CONTENT_LENGTH
            }
          }
      }
  }
 }
$results2 = $null
if ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength").Value -ne $MAX_ALLOWED_CONTENT_LENGTH) {
    $results2 = "maxAllowedContentLength in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($MAX_ALLOWED_CONTENT_LENGTH)"
    if($configurate -and !$skip_config.contains(4.1)) {
      Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value $MAX_ALLOWED_CONTENT_LENGTH
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.1))

$task = '4.2 (L2) Ensure maxURL request filter is configured (Scored)'
$results = $Websites | Foreach-Object {
  $site = $_
  $len = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").requestLimits).Attributes | Where-Object Name -EQ 'maxURL').Value
  if($len -ne $MAX_URL) {
    "Site: $($site.Name)"
    "MaxURL: $len`n"
    if($configurate -and !$skip_config.contains(4.2)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value $MAX_URL
    }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $len = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)$($name)").requestLimits).Attributes | Where-Object Name -EQ 'maxURL').Value
          if($len -ne $MAX_URL) {
            "Site: $($site.Name)$name"
            "MaxURL: $len`n"
            if($configurate -and !$skip_config.contains(4.2)) {
              Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value $MAX_URL
            }
          }
      }
  }
 }
$results2 = $null
if ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxURL").Value -ne $MAX_URL) {
    $results2 = "maxURL in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($MAX_URL)"
    if($configurate -and !$skip_config.contains(4.2)) {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value $MAX_URL
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.2)) -scored $true

$task = '4.3 (L2) Ensure MaxQueryString request filter is configured (Scored)'
$results = $Websites | Foreach-Object {
  $site = $_
  $len = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").requestLimits).Attributes | Where-Object Name -EQ 'maxQueryString').Value
  if($len -ne $MAX_QUERY_STRING) {
    "Site: $($site.Name)"
    "maxQueryString: $len`n"
    if($configurate -and !$skip_config.contains(4.3)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value $MAX_QUERY_STRING
    }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $len = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)$($name)").requestLimits).Attributes | Where-Object Name -EQ 'maxQueryString').Value
          if($len -ne $MAX_QUERY_STRING) {
            "Site: $($site.Name)$name"
            "maxQueryString: $len`n"
            if($configurate -and !$skip_config.contains(4.3)) {
                Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value $MAX_QUERY_STRING
            }
          }
      }
  }
 }
$results2 = $null
if ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString").Value -ne $MAX_QUERY_STRING) {
    $results2 = "MaxQueryString in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($MAX_QUERY_STRING)"
    if($configurate -and !$skip_config.contains(4.3)) {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value $MAX_QUERY_STRING
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.3)) -scored $true

$task = '4.4 (L2) Ensure non-ASCII characters in URLs are not allowed (Scored)'
$results = $Websites | Foreach-Object {
  $site = $_
  $allowed = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").allowHighBitCharacters
  if($allowed -ne $false) {
    "Site: $($site.Name)"
    "AllowHighBitCharacters: $allowed`n"
    if($configurate -and !$skip_config.contains(4.4)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
    }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $allowed = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").allowHighBitCharacters
          if($allowed -ne $false) {
            "Site: $($site.Name)$name"
            "AllowHighBitCharacters: $allowed`n"
            if($configurate -and !$skip_config.contains(4.4)) {
              Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
            }
          }
      }
  }
 }
$results2 = $null
if ((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "MACHINE/WEBROOT/APPHOST").allowHighBitCharacters -ne $false) {
    $results2 = "AllowHighBitCharacters in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($false)"
    if($configurate -and !$skip_config.contains(4.4)) {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.4)) -scored $true

$task = '4.5 (L1) Ensure Double-Encoded requests will be rejected (Scored)'
$results = $Websites | Foreach-Object {
  $site = $_
  $allowed = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").allowDoubleEscaping
  if($allowed -ne $false) {
    "Site: $($site.Name)"
    "allowDoubleEscaping: $allowed`n"
    if($configurate -and !$skip_config.contains(4.5)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
    }
  }
  If ($_.applicationPool) {
      $pools = Get-WebApplication -Site $_.Name
      $pools | ForEach-Object {
          $name = $_.path -replace '/', '\'
          $allowed = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)$name").allowDoubleEscaping
          if($allowed -ne $false) {
            "Site: $($site.Name)$name"
            "allowDoubleEscaping: $allowed`n"
            if($configurate -and !$skip_config.contains(4.5)) {
              Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
            }
          }
      }
  }
 }
$results2 = $null
if ((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "MACHINE/WEBROOT/APPHOST").allowDoubleEscaping -ne $false) {
    $results2 = "allowDoubleEscaping in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($false)"
    if($configurate -and !$skip_config.contains(4.5)) {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.5)) -scored $true

$task = '4.6 (L1) Ensure HTTP Trace Method is disabled (Scored)'
$results = If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
  $Websites | Foreach-Object {
      $site = $_
      $config = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering/verbs' -PSPath "IIS:\sites\$($site.Name)").Collection | Where-Object {$_.verb -eq 'TRACE'}
      If ([string]::IsNullOrEmpty($config) -or $config.allowed -eq $true) {
        "Site: $($site.Name)"
        "allowTraceVerb: $($config.allowed)`n"
        if($configurate -and !$skip_config.contains(4.6)) {
           Add-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering/verbs" -name "." -value @{verb='TRACE';allowed='False'}
        }
      }
      If ($_.applicationPool) {
          $pools = Get-WebApplication -Site $_.Name
          $pools | ForEach-Object {
              $name = $_.path -replace '/', '\'
              $config = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering/verbs' -PSPath "IIS:\sites\$($site.Name)$($name)").Collection | Where-Object {$_.verb -eq 'TRACE'}
              if([string]::IsNullOrEmpty($config) -or $config.allowed -eq $true) {
                "Site: $($site.Name)$name"
                "allowTraceVerb: $($config.allowed)`n"
                if($configurate -and !$skip_config.contains(4.6)) {
                   Add-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering/verbs" -name "." -value @{verb='TRACE';allowed='False'}
                }
              }
          }
      }
  }
} else {
 "Web-Filtering is missing"
}
$results2 = $null
if (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering/verbs' -PSPath "MACHINE/WEBROOT/APPHOST").Collection | Where-Object {$_.verb -eq 'TRACE'}).allowed -ne $false) {
    $results2 = "allowTraceVerb in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($false)"
    if($configurate -and !$skip_config.contains(4.6)) {
      Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/requestFiltering/verbs" -name "." -value @{verb='TRACE';allowed='False'}
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.6)) -scored $true

$task = '4.7 (L1) Ensure Unlisted File Extensions are not allowed (Scored)'
$results = If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
  $Websites | Foreach-Object {
      $site = $_
      $allowed = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted").Value
      If ($allowed -ne $false) {
        "Site: $($site.Name)"
        "AllowUnlisted: $($allowed)`n"
        if($configurate -and !$skip_config.contains(4.7)) {
          Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" -value $false
        }
      }
      If ($_.applicationPool) {
          $pools = Get-WebApplication -Site $_.Name
          $pools | ForEach-Object {
              $name = $_.path -replace '/', '\'
              $allowed = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted").Value
              if($allowed -ne $false) {
                "Site: $($site.Name)$name"
                "AllowUnlisted: $($allowed)`n"
                if($configurate -and !$skip_config.contains(4.7)) {
                  Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" -value $false
                }
              }
          }
      }
  }
} else {
 "Web-Filtering is not missing"
}
$results2 = $null
if ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted").Value -ne $false) {
    $results2 = "AllowUnlisted in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($false)"
    if($configurate -and !$skip_config.contains(4.7)) {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" -value $false
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.7)) -scored $true

$task = '4.8 (L1) Ensure Handler is not granted Write and Script/Execute (Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    $accessPolicy = (Get-WebConfiguration -Filter 'system.webServer/handlers' -PSPath "IIS:\sites\$($site.Name)").accessPolicy
    if($accessPolicy -match '(?i)(Write.*(Execute|Script))|((Execute|Script).*Write)') {
        "Site: $($site.Name)"
        "accessPolicy: $accessPolicy`n"
        if($configurate -and !$skip_config.contains(4.8)) {
            Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)" -filter "system.webServer/handlers" -name "accessPolicy" -value "Read,Script"
        }
    }
    If ($_.applicationPool) {
          $pools = Get-WebApplication -Site $_.Name
          $pools | ForEach-Object {
            $name = $_.path -replace '/', '\'
            $accessPolicy = (Get-WebConfiguration -Filter 'system.webServer/handlers' -PSPath "IIS:\sites\$($site.Name)$name").accessPolicy
            if($accessPolicy -match '(Write.*(Execute|Script))|((Execute|Script).*Write)') {
                "Site: $($site.Name)$name"
                "accessPolicy: $accessPolicy`n"
                if($configurate -and !$skip_config.contains(4.8)) {
                    Set-WebConfigurationProperty -pspath "IIS:\sites\$($site.Name)$name" -filter "system.webServer/handlers" -name "accessPolicy" -value "Read,Script"
                }
            }
          }
      }
}
$results2 = $null
$out = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "accessPolicy"
if ($out -match '(?i)(Write.*(Execute|Script))|((Execute|Script).*Write)') {
    $results2 = "accessPolicy in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($out)"
    if($configurate -and !$skip_config.contains(4.8)) {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "accessPolicy" -value "Read,Script"
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.8)) -scored $true

$task = '4.9 (L1) Ensure notListedIsapisAllowed is set to false (Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    if($(Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$($site.Name)").notListedIsapisAllowed -ne $false) {
        "Site: $($site.Name)"
        "IsapisAllowed: $true`n"
        if($configurate -and !$skip_config.contains(4.9)) {
            Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed" -value $false
        }
    }
    If ($_.applicationPool) {
          $pools = Get-WebApplication -Site $_.Name
          $pools | ForEach-Object {
            $name = $_.path -replace '/', '\'
            if($(Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$($site.Name)$name").notListedIsapisAllowed -ne $false) {
                "Site: $($site.Name)$name"
                "IsapisAllowed: $true`n"
                if($configurate -and !$skip_config.contains(4.9)) {
                    Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed" -value $false
                }
            }
          }
      }
}
$results2 = $null
if ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed").Value -ne $false) {
    $results2 = "notListedIsapisAllowed in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($false)"
    if($configurate -and !$skip_config.contains(4.9)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed" -value $false
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.9)) -scored $true

$task = '4.10 (L1) Ensure notListedCgisAllowed is set to false (Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    if($(Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$($site.Name)").notListedCgisAllowed -ne $false) {
        "Site: $($site.Name)"
        "notListedCgisAllowed: $true`n"
        if($configurate -and !$skip_config.contains(4.10)) {
            Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed" -value $false
        }
    }
    If ($_.applicationPool) {
          $pools = Get-WebApplication -Site $_.Name
          $pools | ForEach-Object {
            $name = $_.path -replace '/', '\'
            if($(Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$($site.Name)$name").notListedCgisAllowed -ne $false) {
                "Site: $($site.Name)$name"
                "notListedCgisAllowed: $true`n"
                if($configurate -and !$skip_config.contains(4.10)) {
                    Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed" -value $false
                }
            }
          }
      }
}
$results2 = $null
if ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed").Value -ne $false) {
    $results2 = "notListedCgisAllowed in machine/webroot/apphost at system.webserver/security/requestfiltering/requestLimits is not set to $($false)"
    if($configurate -and !$skip_config.contains(4.10)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed" -value $false
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.10)) -scored $true

$task = '4.11 (L1) Ensure Dynamic IP Address Restrictions is enabled (Not Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    $config = Get-WebConfiguration -Filter '/system.webServer/security/dynamicIpSecurity' -PSPath "IIS:\sites\$($site.Name)"
    if(($config.denyByConcurrentRequests.enabled -ne $true) -or ($config.denyByConcurrentRequests.maxConcurrentRequests -ne $MAX_CONCURRENT_REQUESTS)) {
        "Site: $($site.Name)"
        "denyByConcurrentRequests: $($config.denyByConcurrentRequests.enabled)"
        "maxConcurrentRequests: $($config.denyByConcurrentRequests.maxConcurrentRequests)`n"
        if($configurate -and !$skip_config.contains(4.11)) {
            Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled" -value $true
            Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests" -value $MAX_CONCURRENT_REQUESTS
        }
    }
    If ($_.applicationPool) {
          $pools = Get-WebApplication -Site $_.Name
          $pools | ForEach-Object {
            $name = $_.path -replace '/', '\'
            $config = Get-WebConfiguration -Filter '/system.webServer/security/dynamicIpSecurity' -PSPath "IIS:\sites\$($site.Name)$name"
            if(($config.denyByConcurrentRequests.enabled -ne $true) -or ($config.denyByConcurrentRequests.maxConcurrentRequests -ne $MAX_CONCURRENT_REQUESTS)) {
                "Site: $($site.Name)$name"
                "denyByConcurrentRequests: $($config.denyByConcurrentRequests.enabled)"
                "maxConcurrentRequests: $($config.denyByConcurrentRequests.maxConcurrentRequests)`n"
                if($configurate -and !$skip_config.contains(4.11)) {
                    Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled" -value $true
                    Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests" -value $MAX_CONCURRENT_REQUESTS
                }
            }
          }
      }
}
$results2 = $null
if (((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled").Value -ne $true) -or ((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests").Value -ne $MAX_CONCURRENT_REQUESTS)) {
    $results2 = "denyByConcurrentRequests in machine/webroot/apphost at system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests is not enabled or its maxConcurrentRequests is not set to $($MAX_CONCURRENT_REQUESTS)"
    if($configurate -and !$skip_config.contains(4.11)) {
        Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled" -value $true
        Set-WebConfigurationProperty -pspath "IIS:\sites" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests" -value $MAX_CONCURRENT_REQUESTS
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results) -and [string]::IsNullOrEmpty($results2)) -taskName $task -failMsg ($results+$results2) -changed (!$skip_config.contains(4.11))

Write-Output ''
}

if (($check_only.count -eq 0) -or ($check_only.contains(5))) {

$task = '5.1 (L1) Ensure Default IIS web log location is moved (Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    if($site.logFile.directory -match ("^($($env:systemdrive)|%SystemDrive%)")) {
        "Site: $($site.Name)"
        "logFile directory: $($site.logFile.directory)`n"
    } 
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(5.1)) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "directory" -value $LOGS_DIR
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(5.1)) -scored $true

$task = '5.2 (L1) Ensure Advanced IIS logging is enabled (Scored)'
$fields = 'Date,Time,ClientIP,UserName,(SiteName,)?(ComputerName,)?ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,(ProtocolVersion,)?Host,HttpSubStatus'
$fieldsFlagValue = 3669967
$results = $Websites | Foreach-Object {
    $site = $_
    $currentLoggingFields = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name=`"$($site.Name)`"]/LogFile" -Name LogExtFileFlags
    if($currentLoggingFields -notmatch $fields) {
        "Site: $($site.Name)"
        "Logging Fields: $currentLoggingFields`n"
        "Should be     : $fields"
        if($configurate -and !$skip_config.contains(5.2)) {
            Set-ItemProperty "IIS:\Sites\$($site.Name)" -name LogFile.logExtFileFlags -value 3669967
        }
    } 
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(5.2)) -scored $true

$task = '5.3 (L1) Ensure ETW Logging is enabled (Not Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    if($site.logFile.logTargetW3C -notmatch ("^\s*(File\s*,\s*ETW)|(ETW\s*,\s*File)\s*$")) {
        "Site: $($site.Name)"
        "logTargetW3C: $($site.logFile.logTargetW3C)`n"
    } 
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(5.3)) {
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logTargetW3C" -value "File,ETW"
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(5.3))

Write-Output ''
}

if (($check_only.count -eq 0) -or ($check_only.contains(6))) {

$task = '6.1 (L1) Ensure FTP requests are encrypted (Not Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    $config = (Get-WebConfiguration -Filter 'system.applicationHost/sites' -PSPath "IIS:\sites\$($_.Name)").siteDefaults.ftpServer.security.ssl
    if(($config.controlChannelPolicy -notmatch ('^SslRequire$')) -or ($config.dataChannelPolicy -notmatch ('^SslRequire$'))) {
        "Site: $($site.Name)"
        "dataChannelPolicy: $($config.dataChannelPolicy)"
        "controlChannelPolicy: $($config.controlChannelPolicy)`n"
    }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(6.1)) {
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "controlChannelPolicy" -value "SslRequire"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "dataChannelPolicy" -value "SslRequire"
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(6.1))

$task = '6.2 (L1) Ensure FTP Logon attempt restrictions is enabled (Not Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    $config = (Get-WebConfiguration -Filter 'system.ftpServer/security/authentication' -PSPath "IIS:\sites\$($_.Name)")
    if(($config.denyByFailure.enabled -ne $true)) {
        "Site: $($site.Name)"
        "denyByFailure: $($config.denyByFailure.enabled)`n"
    }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(6.2)) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.ftpServer/security/authentication/denyByFailure" -name "enabled" -value $true
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(6.2))

write-output ''
}

if (($check_only.count -eq 0) -or ($check_only.contains(7))) {

$task = '7.1 (L2) Ensure HSTS Header is set (Not Scored)'
$results = $Websites | Foreach-Object {
    $site = $_
    $config = (Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name=`"$($_.Name)`"]" -Name hsts)
    if(($config.enabled -ne $true) -or ($config.'max-age' -ne $HSTS_MAX_AGE)) {
        "Site: $($site.Name)"
        "enabled: $($config.enabled)"
        "max-age: $($config.'max-age')`n"
        if($configurate -and !$skip_config.contains(7.1)) {
           Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name=`"$($_.Name)`"]/hsts" -Name enabled -Value $true
           Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name=`"$($_.Name)`"]/hsts" -Name 'max-age' -Value $HSTS_MAX_AGE
        }
    }
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.1))


$task = '7.2 (L1) Ensure SSLv2 is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
$path2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
$results = $null
if(!(Test-Path $path1) -or !(Test-Path $path2)) {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.2)) {
    New-Item $path2 -Force | Out-Null
    New-Item $path1 -Force | Out-Null
  }
} else {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $rg2 = (Get-ItemProperty -path $path2).Enabled
  $rg3 = (Get-ItemProperty -path $path1).DisabledByDefault
  $rg4 = (Get-ItemProperty -path $path2).DisabledByDefault
  if (($rg1 -ne 0) -or ($rg2 -ne 0) -or ($rg3 -ne 1) -or ($rg4 -ne 1)) {
      $results = "Client_Enabled: $($rg1)`nClient_DisabledByDefault:$($rg3)`nServer_Enabled: $($rg2)`nServer_DisabledByDefault: $($rg4)`n`nShould be: 0 0 1 1"
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.2)) {
    New-ItemProperty -path $path2 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path2 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.2)) -scored $true

$task = '7.3 (L1) Ensure SSLv3 is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
$path2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
$results = $null
if((Test-Path $path1) -and (Test-Path $path2)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $rg2 = (Get-ItemProperty -path $path2).Enabled
  $rg3 = (Get-ItemProperty -path $path1).DisabledByDefault
  $rg4 = (Get-ItemProperty -path $path2).DisabledByDefault
  if (($rg1 -ne 0) -or ($rg2 -ne 0) -or ($rg3 -ne 1) -or ($rg4 -ne 1)) {
      $results = "Client_Enabled: $($rg1)`nClient_DisabledByDefault:$($rg3)`nServer_Enabled: $($rg2)`nServer_DisabledByDefault: $($rg4)`n`nShould be: 0 0 1 1"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.3)) {
    New-Item $path2 -Force | Out-Null
    New-Item $path1 -Force | Out-Null
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.3)) {
    New-ItemProperty -path $path2 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path2 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.3)) -scored $true

$task = '7.4 (L1) Ensure TLS 1.0 is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
$path2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
$results = $null
if((Test-Path $path1) -and (Test-Path $path2)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $rg2 = (Get-ItemProperty -path $path2).Enabled
  $rg3 = (Get-ItemProperty -path $path1).DisabledByDefault
  $rg4 = (Get-ItemProperty -path $path2).DisabledByDefault
  if (($rg1 -ne 0) -or ($rg2 -ne 0) -or ($rg3 -ne 1) -or ($rg4 -ne 1)) {
      $results = "Client_Enabled: $($rg1)`nClient_DisabledByDefault:$($rg3)`nServer_Enabled: $($rg2)`nServer_DisabledByDefault: $($rg4)`n`nShould be: 0 0 1 1"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.4)) {
    New-Item $path2 -Force | Out-Null
    New-Item $path1 -Force | Out-Null
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.4)) {
    New-ItemProperty -path $path2 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path2 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.4)) -scored $true

$task = '7.5 (L1) Ensure TLS 1.1 is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
$path2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
$results = $null
if((Test-Path $path1) -and (Test-Path $path2)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $rg2 = (Get-ItemProperty -path $path2).Enabled
  $rg3 = (Get-ItemProperty -path $path1).DisabledByDefault
  $rg4 = (Get-ItemProperty -path $path2).DisabledByDefault
  if (($rg1 -ne 0) -or ($rg2 -ne 0) -or ($rg3 -ne 1) -or ($rg4 -ne 1)) {
      $results = "Client_Enabled: $($rg1)`nClient_DisabledByDefault:$($rg3)`nServer_Enabled: $($rg2)`nServer_DisabledByDefault: $($rg4)`n`nShould be: 0 0 1 1"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.5)) {
    New-Item $path2 -Force | Out-Null
    New-Item $path1 -Force | Out-Null
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.5)) {
    New-ItemProperty -path $path2 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path2 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.5)) -scored $true

$task = '7.6 (L1) Ensure TLS 1.2 is Enabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
$results = $null
if((Test-Path $path1)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $rg2 = (Get-ItemProperty -path $path1).DisabledByDefault
  $results = $null
  if (($rg1 -ne 1) -or ($rg2 -ne 0)) {
    $results = "Server_Enabled: $($rg1)`nServer_DisabledByDefault: $($rg2)`n`nShould be: 1 0"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.6)) {
    New-Item $path1 -Force | Out-Null
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.6)) {
    New-ItemProperty -path $path1 -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path1 -name 'DisabledByDefault' -value '0' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.6)) -scored $true

$task = '7.7 (L1) Ensure NULL Cipher Suites is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'
if((Test-Path $path1)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $results = $null
  if (($rg1 -ne 0)) {
    $results = "Cipher Enabled: $($rg1)`n`nShould be: 0"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.7)) {
    New-Item $path1 -Force | Out-Null
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.7)) {
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.7)) -scored $true

$task = '7.8 (L1) Ensure DES Cipher Suites is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'
if((Test-Path $path1)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $results = $null
  if (($rg1 -ne 0)) {
    $results = "Cipher Enabled: $($rg1)`n`nShould be: 0"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.8)) {
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('DES 56/56')
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.8)) {
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.8)) -scored $true

$task = '7.9 (L1) Ensure RC4 Cipher Suites is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
$path2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
$path3 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
$path4 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
if((Test-Path $path1) -and (Test-Path $path2)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $rg2 = (Get-ItemProperty -path $path2).Enabled
  $rg3 = (Get-ItemProperty -path $path3).Enabled
  $rg4 = (Get-ItemProperty -path $path4).Enabled
  $results = $null
  if (($rg1 -ne 0) -or ($rg2 -ne 0) -or ($rg3 -ne 0) -or ($rg4 -ne 0)) {
      $results = "RC4 40/128: $($rg1)`nRC4 56/128:$($rg2)`nRC4 64/128: $($rg3)`nRC4 128/128: $($rg4)`n`nShould be: 0 0 0 0"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.9)) {
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 40/128')
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 56/128')
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 64/128')
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 128/128')
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.9)) {
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path2 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path3 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path4 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.9)) -scored $true

$task = '7.10 (L1) Ensure AES 128/128 Cipher Suite is Disabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
if((Test-Path $path1)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $results = $null
  if (($rg1 -ne 0)) {
    $results = "Cipher Enabled: $($rg1)`n`nShould be: 0"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.10)) {
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 128/128')
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.10)) {
    New-ItemProperty -path $path1 -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.10)) -scored $true

$task = '7.11 (L1) Ensure AES 256/256 Cipher Suite is Enabled (Scored)'
$path1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
if((Test-Path $path1)) {
  $rg1 = (Get-ItemProperty -path $path1).Enabled
  $results = $null
  if (($rg1 -ne 1)) {
    $results = "Cipher Enabled: $($rg1)`n`nShould be: 1"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.11)) {
    (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 256/256')
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.11)) {
    New-ItemProperty -path $path1 -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.11)) -scored $true

$task = '7.12 (L2) Ensure TLS Cipher Suite ordering is Configured (Scored)'
$path1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
if((Test-Path $path1)) {
  $rg1 = (Get-ItemProperty -path $path1).Functions
  $results = $null
  if (($rg1 -ne $CIPHER_SUITE_ORDERED)) {
    $results = "Wrong order or incomplite cipher suite list. Should be:`n$($CIPHER_SUITE_ORDERED)"
  }
} else {
  $results = "Registry entries do not exist (not created)!"
  if($configurate -and !$skip_config.contains(7.12)) {
    New-Item $path1 -Force | Out-Null
  }
}
if(![string]::IsNullOrEmpty($results) -and $configurate -and !$skip_config.contains(7.12)) {
    New-ItemProperty -path $path1 -name 'Functions' -value $CIPHER_SUITE_ORDERED -PropertyType 'MultiString' -Force | Out-Null
}
Print-Results -passed ([string]::IsNullOrEmpty($results)) -taskName $task -failMsg ($results) -changed (!$skip_config.contains(7.12)) -scored $true

}

Write-Host "`nThe final score for your configuration is $($Score) out of 42 (~$([math]::Round(($Score/42 *100), 2))% complient with SCORED recommendations)" -ForegroundColor Cyan