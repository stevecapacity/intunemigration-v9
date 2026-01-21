<#
INTUNE DEVICE MIGRATION V9

    .FIXES 
        Added logic to check registry to allow provisioning packages
        Added detailed logging to installing provisioning package
    .SYNOPSIS
        Intune Device Migration Script (Version 9)

    .DESCRIPTION
        Automates migration of device settings and files for Intune onboarding, including tenant authentication, registry configuration, and file operations.

    .AUTHOR
        Steve Capacity

    .VERSION
        1.0

    .DATE
        October 27, 2025
#>

# Intune Device Migration V9

# Import utils module
. "$($PSScriptRoot)\utils.ps1"

$ErrorActionPreference = "SilentlyContinue"

# Import configuration file
$config = Get-Content ".\config.json" | ConvertFrom-Json

Start-Transcript -Path "$($config.logPath)\startMigrate.log" -Verbose

log info "Importing config file"
log info "Starting log..."

# Check for local path and create
$localPath = "$($config.localPath)"
if (-not (Test-Path $localPath)) {
    log info "Creating local path $localPath"
    New-Item -Path $localPath -ItemType Directory
}
else {
    log info "Local path $localPath already exists"
}

# Set install tag for Intune
log info "Setting Intune detection rule"
New-Item -ItemType File -Path "$($localPath)\IntuneDetectionRule.txt" -Force
log info "Intune detection rule set to $($localPath)\IntuneDetectionRule.txt"


# Check context
$context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
log info "Running as $($context)"
$systemSIDs = @("S-1-5-18") # SID for NT AUTHORITY\SYSTEM
$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

if ($currentSID -notin $systemSIDs) {
    log error "Script must be run in system context. Exiting..."
    exit 1
}

#Check PeferredDomainList
$prefDomain = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\AzureADAccount -Name PreferredTenantDomainName
If ($prefDomain -ne $null) {
    log error "Preferred tenant domain set to $prefDomain"
    log error "Set Intune Device Category to Premigrate, Intune resync, retry."
    exit 1
}
log info "No preferred tenant domain set...continuing"

#Check user profiles for mutliple entries
#########################################
$UsersPath = "C:\Users"
$Profiles = Get-ChildItem $UsersPath -Directory |
Where-Object {
    $_.Name -notin @(
        "Public",
        "Default",
        "Default User",
        "All Users",
        "Administrator"
    )
}

$Seen = @{}

foreach ($Prof in $Profiles) {

    # Base name = everything before the first dot
    $BaseName = ($Prof.Name -split '\.')[0].ToLower()

    # If we've already seen this base name, exit
    if ($Seen.ContainsKey($BaseName)) {
        log error "Duplicate user profile detected: '$BaseName'"
        log error "Existing profile: $($Seen[$BaseName])"
        log error  "Duplicate profile: $($Prof.FullName)"
        exit 1
    }
    # Record first occurrence
    $Seen[$BaseName] = $Prof.FullName
}

log info "No duplicate user profiles found. Continuing script..."

# Copy package files to local path
log info "Copying package files to local path"
$sourcePath = ".\*"
$files = Get-ChildItem -Path $sourcePath -Recurse
$destination = $localPath
foreach ($file in $files) {
    log info "Copying $($file.FullName) to $destination..."
    try {
        Copy-Item -Path $file.FullName -Destination $destination -Recurse -Force
        log success "Copied $($file.FullName) to $destination"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to copy $($file.FullName) to $($destination): $message"
    }
}

# Authenticate to source tenant
log info "Checking configuration for source tenant..."
if ([string]::IsNullOrEmpty($config.sourceTenant.tenantName)) {
    log warning "Source tenant not found in configuration"
    log warning "Exiting script"
    exit
} 
else {
    log info "Source tenant found in configuration..."
    try {
        log info "Authenticating to source tenant $($config.sourceTenant.tenantName)..."
        $sourceHeaders = msGraphAuthenticate -tenantName $config.sourceTenant.tenantName -clientId $config.sourceTenant.clientId -clientSecret $config.sourceTenant.clientSecret
        log success "Authenticated to source tenant $($config.sourceTenant.tenantName)"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to authenticate to source tenant $($config.sourceTenant.tenantName): $message"
        log error "Exiting script"
        exit
    }
}


# Authenticate to destination tenant
log info "Checking configuration for destination tenant..."
if ([string]::IsNullOrEmpty($config.targetTenant.tenantName)) {
    log warning "Destination tenant not found in configuration..."
    log warning "Proceeding with Domain to Cloud migration"
    $targetHeaders = $null
}
else {
    log info "Destination tenant found in configuration file"
    try {
        log info "Authenticating to destination tenant $($config.targetTenant.tenantName)..."
        $targetHeaders = msGraphAuthenticate -tenantName $config.targetTenant.tenantName -clientId $config.targetTenant.clientId -clientSecret $config.targetTenant.clientSecret
        log success "Authenticated to destination tenant $($config.targetTenant.tenantName)"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to authenticate to destination tenant $($config.targetTenant.tenantName): $message"
        log error "Exiting script"
        exit
    }
}

# Set registry to allow adding provisioning packages
log info "Enabling Allow Provisioning packages in registry..."
try {
    setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Security" -regName "AllowAddProvisioningPackage" -regValue 1
    log success "Successfully set AllowAddProvisioningPackage to 1 in registry"
}
catch {
    $message = $_.Exception.Message
    log error "Failed to set AllowAddProvisioningPackage to 1 in registry: $message"
    log error "Exiting script"
    exit 1
}

# Set Microsoft account connection registry key
log info "Checking Microsoft account connection registry key..."
try {
    setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts" -regName "AllowMicrosoftAccountConnection" -regValue 1
    log success "Successfully set AllowMicrosoftAccountConnection to 1"
}
catch {
    $message = $_.Exception.Message
    log warning "Failed to set AllowMicrosoftAccountConnection to 1: $message"
    log warning "May cause problems with migration"
}

# Create the PC Object
$hostname = $env:COMPUTERNAME
$azureAdJoined = (dsregcmd.exe /status | Select-String "AzureAdJoined").ToString().Split(":")[1].Trim()
$domainJoined = (dsregcmd.exe /status | Select-String "DomainJoined").ToString().Split(":")[1].Trim()
$certPath = "Cert:\LocalMachine\My"
$intuneIssuer = "Microsoft Intune MDM Device CA"
$autopilotRegPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot"
$autopilotRegName = "CloudAssignedMdmId"
$autopilotRegValue = Get-ItemProperty -Path $autopilotRegPath -Name $autopilotRegName -ErrorAction SilentlyContinue
$mdm = $false

# Check if device is intune managed
$intuneCert = Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $intuneIssuer }
log info "Checking for Intune certificate..."
if ($intuneCert) {
    log info "Intune certificate found"
    $mdm = $true
    $intuneId = (($intuneCert | Select-Object Subject).Subject).TrimStart("CN=")
    log info "Intune ID: $intuneId"
    log info "$hostname is Intune managed"
}
else {
    log info "Device is not managed by Intune"
    $intuneId = $null
}

# Check if device is Autopilot registered
log info "Checking for Autopilot registration..."
if ($autopilotRegValue) {
    log info "Autopilot registration found"
    $autopilotId = (Get-ItemProperty -Path "$($autopilotRegPath)\EstablishedCorrelations" -Name "ZtdRegistrationId").ZtdRegistrationId
    log info "Autopilot ID: $($autopilotId)"
}
else {
    log info "Autopilot registration not found"
    $autopilotId = $null
}

# Check if device is domain joined
log info "Checking if domain joined..."
if ($domainJoined -eq "Yes") {
    log info "$hostname is domain joined"
    $localDomain = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Domain").Domain
    log info "Domain: $localDomain"
}
else {
    log info "$hostname is not domain joined"
    $localDomain = $null
}

$pc = @{
    hostname      = $hostname
    intuneId      = $intuneId
    domainJoined  = $domainJoined
    localDomain   = $localDomain
    autopilotId   = $autopilotId
    azureAdJoined = $azureAdJoined
    mdm           = $mdm
}

log info "Writing PC object to registry..."
foreach ($x in $pc.Keys) {
    $pcName = "OLD_$($x)"
    $pcValue = $($pc[$x])
    # Check if value is null or empty
    if ([string]::IsNullOrEmpty($pcValue)) {
        log warning "$pcName is null or empty"
        log warning "Not writing to registry"
    }
    else {
        log info "$($pcName): $($pcValue)"
        reg.exe add $($config.regPath) /v $pcName /t REG_SZ /d $pcValue /f | Out-Null
        log success "$pcName written to registry with value: $pcValue"
    }
}

# Get user info
$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName
$SID = (New-Object System.Security.Principal.NTAccount($userName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath")
$SAMName = ($userName).Split("\")[1]

# If PC is not domain joined, get UPN from cache
if ($pc.azureAdJoined -eq "Yes") {
    $upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($SID)\IdentityCache\$($SID)" -Name "UserName")
    log info "User UPN is $upn"
    log info "Getting $upn Entra Object ID..."
    try {
        $entraUserId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $sourceHeaders).id
        log success "Entra Object ID is $($entraUserId)"        
    }
    catch {
        $entraUserId = $null
        $message = $_.Exception.Message
        log warning "Failed to get user Entra Object ID"
        log warning "May cause issues with migration"
    }
}
else {
    log info "System is not Entra joined - setting UPN and Entra User Object ID values to null"
    $upn = $null
    $entraUserId = $null
}

$currentUser = @{
    userName    = $userName
    upn         = $upn
    entraUserId = $entraUserId
    profilePath = $profilePath
    SAMName     = $SAMName
    SID         = $SID
}

# Write user object to registry
foreach ($x in $currentUser.Keys) {
    $currentUserName = "OLD_$($x)"
    $currentUserValue = $($currentUser[$x])
    # Check if value is null or empty
    if ([string]::IsNullOrEmpty($currentUserValue)) {
        log warning "$($currentUserName) is empty"
        log warning "Skipping registry write for $($currentUserName)"
    }
    else {
        log "Writing $($currentUserName) with value $($currentUserValue) to registry..."
        try {
            reg.exe add $($config.regPath) /v $currentUserName /t REG_SZ /d $currentUserValue /f | Out-Null
            log success "Successfully wrote $($currentUserName) with value $($currentUserValue) to registry."
        }
        catch {
            $message = $_.Exception.Message
            log error "Failed to write $($currentUserName) to registry: $message"
        }
    }
}

# USER SIGN IN TO VERIFY CREDENTIALS AND GET TARGET TENANT SID
$installedNuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
if (-not($installedNuget)) {
    log info "NuGet package provider not installed.  Installing..."
    Install-PackageProvider -Name NuGet -Force
    log info "NuGet package provider installed successfully."
}
else {
    log info "NuGet package provider already installed."
}
# Check for Az.Accounts module
$modules = ("Az.Accounts", "RunAsUser")
foreach ($module in $modules) {
    $installedModule = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue
    if (-not($installedModule)) {
        log info "$module module not installed.  Installing..."
        if ($module -eq "Az.Accounts") {
            Install-Module -Name $module -RequiredVersion "4.2.0" -Force
            log info "Az.Accounts module version 4.2.0 installed successfully."
        }
        else {
            Install-Module -Name $module -Force
            log info "$module module installed successfully."
        }
    }
    else {
        if ($module -eq "Az.Accounts" -and $installedModule.Version -ge "5.0.0") {
            log info "Uninstalling newer version of $($module)..."
            Uninstall-Module -Name $module -AllVersions -Force
            log info "Installing $($module) version 4.2.0..."
            Install-Module -Name $module -RequiredVersion "4.2.0" -Force
            log success "Az.Accounts module version 4.2.0 installed successfully."
        }
        else {
            log info "$module module already installed."
        }
    }
}
$scriptBlock = {
    Import-Module Az.Accounts

    #Get Token form OAuth
    Clear-AzContext -Force
    Update-AzConfig -EnableLoginByWam $false -LoginExperienceV2 Off
    Connect-AzAccount
    $theToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"

    #Get Token form OAuth
    $token = -join ("Bearer ", $theToken.Token)

    #Reinstantiate headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")

    $newUserObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/me" -Headers $headers -Method "GET"

    $newUser = @{
        upn         = $newUserObject.userPrincipalName
        entraUserId = $newUserObject.id
        SAMName     = $newUserObject.userPrincipalName.Split("@")[0]
        SID         = $newUserObject.securityIdentifier
    } | ConvertTo-Json

    $newUser | Out-File "C:\Users\Public\Documents\newUserInfo.json"
}
$newUserPath = "C:\Users\Public\Documents\newUserInfo.json"
$timeout = 300
$checkInterval = 5
$elapsedTime = 0
Invoke-AsCurrentUser -ScriptBlock $scriptBlock -UseWindowsPowerShell
while ($elapsedTime -lt $timeout) {
    if (Test-Path $newUserPath) {
        log info "New user found.  Continuing with script..."
        $elapsedTime = $timeout
        break
    }
    else {
        log info "New user info not present.  Waiting for user to sign in..."
        Start-Sleep -Seconds $checkInterval
        $elapsedTime += $checkInterval
    }
}
if (Test-Path $newUserPath) {
    log info "New user info found at $newUserPath"
    $newUserInfo = Get-Content -Path "C:\Users\Public\Documents\newUserInfo.json" | ConvertFrom-JSON

    $newUser = @{
        entraUserID = $newUserInfo.entraUserId
        SID         = $newUserInfo.SID
        SAMName     = $newUserInfo.SAMName
        UPN         = $newUserInfo.upn
    }
    foreach ($x in $newUser.Keys) {
        $newUserName = "NEW_$($x)"
        $newUserValue = $($newUser[$x])
        if (![string]::IsNullOrEmpty($newUserValue)) {
            log info "Writing $($newUserName) with value $($newUserValue)..."
            try {
                reg.exe add "HKLM\SOFTWARE\IntuneMigration" /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
                log success "Successfully wrote $($newUserName) with value $($newUserValue)."
            }
            catch {
                $message = $_.Exception.Message
                log error "Failed to write $($newUserName) with value $($newUserValue).  Error: $($message)."
                log error "Exiting script"
                exit 1
            }
        }
    }
    Write-Host "User found. Continuing with script..."
    Remove-Item -Path $newUserPath -Force -Recurse
}
else {
    log error "User not found.  Exiting script."
    exit 1
}

# Remove MDM cert
if ($intuneCert) {
    log info "Removing MDM certificate..."
    $intuneCert | Remove-Item
    log info "MDM Certificate removed"
}
else {
    log info "MDM certificate not found"
}

# Remove MDM enrollment
if ($pc.mdm -eq $true) {
    log info "Removing MDM enrollment..."
    $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
    $enrollments = Get-ChildItem -Path $enrollmentPath
    foreach ($enrollment in $enrollments) {
        $object = Get-ItemProperty Registry::$enrollment
        $enrollPath = $enrollmentPath + $object.PSChildName
        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
        if ($key) {
            log info "Removing MDM enrollment $($enrollPath)..."
            Remove-Item -Path $enrollPath -Recurse
            log info "MDM enrollment removed successfully"
        }
        else {
            log info "MDM enrollment not found"
        }
    }
    $enrollId = $enrollPath.Split("\")[-1]
    $additionalPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$($enrollID)"
    )
    foreach ($path in $additionalPaths) {
        if (Test-Path $path) {
            log info "Removing $($path)..."
            Remove-item -Path $path -Recurse
            log info "$($path) removed successfully"
        }
        else {
            log info "$($path) not found"
        }
    }
}
else {
    log info "MDM enrollment not found"
}

# Set migration tasks
$tasks = @("reboot", "postMigrate")
foreach ($task in $tasks) {
    $taskPath = "$($localPath)\$($task).xml"
    if ([string]::IsNullOrEmpty($taskPath)) {
        log info "$($task) not found"
    }
    else {
        log info "Setting $($task) task..."
        try {
            schtasks.exe /create /xml $taskPath /tn $task /f | Out-Host
            log info "$($task) successfully created"
        }
        catch {
            $message = $_.Exception.Message
            log error "Failed to set $($task) task: $message"
            log error "Exiting script"
            exit 1
        }
    }
}

# Leave AzureAD/Entra Join
if ($pc.azureAdJoined -eq "YES") {
    log info "PC is Azure AD joined. Leaving..."
    try {
        Start-Process -FilePath "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave"
        log success "PC left Azure AD successfully"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to leave Azure AD: $message"
        log error "Exiting script"
        exit 1
    }
}
else {
    log info "PC is not Azure AD joined"
}

# Leave domain/hybrid join

# Set local migration admin
$migrateAdmin = "MigrationInProgress"
$adminPW = generatePassword
$adminGroup = Get-CimInstance -Query "Select * From Win32_Group Where LocalAccount = True And SID = 'S-1-5-32-544'"
$adminGroupName = $adminGroup.Name
New-LocalUser -Name $migrateAdmin -Password $adminPW -PasswordNeverExpires
Add-LocalGroupMember -Group $adminGroupName -Member $migrateAdmin

if ($pc.domainJoined -eq "YES") {
    $hostname = $pc.hostname
    $localDomain = $pc.localDomain

    # Check for line of sight to domain controller
    $pingCount = 4

    # Check connection based on PowerShell version
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        $pingResult = Test-Connection -ComputerName $localDomain -Count $pingCount
    }
    else {
        $pingResult = Test-Connection -TargetName $localDomain -Count $pingCount
    }
    if ($pingResult.StatusCode -eq 0) {
        log info "$($hostname) has line of sight to domain controller. Attempting to break..."
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty InterfaceAlias
        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses ("8.8.8.8", "8.8.4.4")
        log info "Broke line of sight to domain controller"
    }
    else {
        log info "$($hostname) has no line of sight to domain controller"
    }
    log info "Checking $MigrateAdmin status..."
    $acctStatus = (Get-LocalUser -Name $migrateAdmin).Enabled
    if ($acctStatus -eq $false) {
        log info "$($migrateAdmin) is disabled; enabling"
        Get-LocalUser -Name $migrateAdmin | Enable-LocalUser
        log info "Successfully enabled $migrateAdmin"
    }
    else {
        log info "$migrateAdmin is already enabled"
    }
    try {
        # Try to leave domain
        $instance = Get-CimInstance -ClassName 'Win32_ComputerSystem'
        $invCimParams = @{
            MethodName = 'UnjoinDomainOrWorkGroup'
            Arguments  = @{ FUnjoinOptions = 0; Username = "$hostname\$migrateAdmin"; Password = "$adminPW" }
        }
        $instance | Invoke-CimMethod @invCimParams
        log success "Successfully unjoined $hostname from domain"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to unjoin $hostname from domain. Error: $message"
        log error "Exiting script"
        Exit 1
    }
}
else {
    log "PC is not domain joined"
}

# FUNCTION: removeSCCM
# DESCRIPTION: Removes the SCCM client from the device.
function removeSCCM() {
    [CmdletBinding()]
    Param(
        [string]$CCMpath = "C:\Windows\ccmsetup\ccmsetup.exe",
        [array]$services = @("CcmExec", "smstsmgr", "CmRcService", "ccmsetup"),
        [string]$CCMProcess = "ccmsetup",
        [string]$servicesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\",
        [string]$ccmRegPath = "HKLM:\SOFTWARE\Microsoft\CCM",
        [array]$sccmKeys = @("CCM", "SMS", "CCMSetup"),
        [string]$CSPPath = "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP",
        [array]$sccmFolders = @("C:\Windows\ccm", "C:\Windows\ccmsetup", "C:\Windows\ccmcache", "C:\Windows\ccmcache2", "C:\Windows\SMSCFG.ini",
            "C:\Windows\SMS*.mif"),
        [array]$sccmNamespaces = @("ccm", "sms")
    )
    
    # Remove SCCM client
    log info "Removing SCCM client..."
    if (Test-Path $CCMpath) {
        log info "Uninstalling SCCM client..."
        Start-Process -FilePath $CCMpath -ArgumentList "/uninstall" -Wait
        if ($CCMProcess) {
            log info "SCCM client still running; killing..."
            Stop-Process -Name $CCMProcess -Force -ErrorAction SilentlyContinue
            log info "Killed SCCM client."
        }
        else {
            log info "SCCM client uninstalled successfully."
        }
        # Stop SCCM services
        foreach ($service in $services) {
            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceStatus) {
                log info "Stopping $service..."
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                log info "Stopped $service."
            }
            else {
                log info "$service not found."
            }
        }
        # Remove WMI Namespaces
        foreach ($namespace in $sccmNamespaces) {
            Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name = '$namespace'" -Namespace "root" | Remove-WmiObject
        }
        # Remove SCCM registry keys
        foreach ($service in $services) {
            $serviceKey = $servicesRegPath + $service
            if (Test-Path $serviceKey) {
                log info "Removing $serviceKey registry key..."
                Remove-Item -Path $serviceKey -Recurse -Force -ErrorAction SilentlyContinue
                log info "Removed $serviceKey registry key."
            }
            else {
                log info "$serviceKey registry key not found."
            }
        }
        foreach ($key in $sccmKeys) {
            $keyPath = $ccmRegPath + "\" + $key
            if (Test-Path $keyPath) {
                log info "Removing $keyPath registry key..."
                Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue
                log info "Removed $keyPath registry key."
            }
            else {
                log info "$keyPath registry key not found."
            }
        }
        # Remove CSP
        Remove-Item -Path $CSPPath -Recurse -Force -ErrorAction SilentlyContinue
        # Remove SCCM folders
        foreach ($folder in $sccmFolders) {
            if (Test-Path $folder) {
                log info "Removing $folder..."
                Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                log info "Removed $folder."
            }
            else {
                log info "$folder not found."
            }
        }
    }
    else {
        log info "SCCM client not found."
    }
}


# Remove SCCM client if required
log info "Checking for SCCM client..."
if ($config.SCCM -eq $true) {
    log info "SCCM enabled.  Removing SCCM client..."
    try {
        removeSCCM
        log success "SCCM client removed successfully."
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to remove SCCM client. Error: $message"
        log error "Exiting script."
        Exit 1
    }
}
else {
    log info "SCCM not enabled."
}

# Delete source tenant objects
if ($pc.intuneId) {
    log info "Deleting Intune object..."
    $intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($pc.intuneId)"
    try {
        Invoke-RestMethod -Method DELETE -Uri $intuneUri -Headers $sourceHeaders
        Start-Sleep -Seconds 60
        log success "Intune object deleted successfully"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to delete Intune object: $message"
        log warning "Please delete manually"
    }
}
else {
    log info "Intune object not found"
}

if ($pc.autopilotId) {
    log info "Deleting Autopilot object..."
    $autopilotUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($pc.autopilotId)"
    try {
        Invoke-RestMethod -Method DELETE -Uri $autopilotUri -Headers $sourceHeaders
        log info "Check if $($pc.hostname) was removed from Autopilot"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to delete Autopilot object: $message"
        log warning "Please delete manually."
    }
}
else {
    log info "Autopilot object not found"
}

# Install provisioning package
$ppkg = (Get-ChildItem -Path $config.localPath -Filter "*.ppkg" -Recurse).FullName
if ($ppkg) {
    log info "Provisioning package found. Proceeding..."
    # Check for existing packages
    log info "Checking for existing provisioning packages..."
    try {
        $existingPackages = Get-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue
        if ($existingPackages) {
            log info "Found $($existingPackages.Count) existing provisioning package(s). Removing..."
            foreach ($existingPkg in $existingPackages) {
                log info "Removing existing package: $($existingPkg.PackageName)"
                Remove-ProvisioningPackage -PackageId $existingPkg.PackageId -AllInstalledPackages -Force
            }
        }
        else {
            log info "No existing provisioning packages found."
        }
    }
    catch {
        $message = $_.Exception.Message
        log warning "Could not check for existing provisioning packages: $message"
    }

    log info "Installing Migration Provisioning Package..."
    try {
        Start-Sleep -Seconds 1
        Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -Force -LogsDirectoryPath $config.logPath

        # Verify installation
        Start-Sleep -Seconds 5
        $installedPackages = Get-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue
        if ($installedPackages) {
            log success "Provisioning package installed successfully. Installed packages:"
            foreach ($pkg in $installedPackages) {
                log info " - Package: $($pkg.PackageName), ID: $($pkg.PackageId)"
            }
        }
        else {
            log error "Provisioning package installation completed but no packages were found in the installed list."
            log error "Exiting script"
            exit 1
        }
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to install provisioning package. Error: $message"

        # try with DISM
        log info "Attempting an alternate installation method using DISM..."
        try {
            $dismResult = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Add-ProvisioningPackage /PackagePath:$($ppkg)" -Wait -PassThru -NoNewWindow
            if ($dismResult.ExitCode -eq 0) {
                log success "Provisioning package installed successfully using DISM"
            }
            else {
                log error "DISM installation also failed with exit code: $($dismResult.ExitCode)"
                log error "Exiting script"
                exit 1
            }
        }
        catch {
            $message = $_.Exception.Message
            log error "DISM installation failed: $($message)"
            log error "Exiting script."
            exit 1
        }
    }
}
else {
    log error "Provisioning package not found in $($config.localPath)"
    log error "Exiting script"
    exit 1
}

# Set autologon
log info "Setting auto logon policy"
$autoLogonSettings = @{
    "AutoAdminLogon"  = 1
    "DefaultUserName" = $migrateAdmin
    "DefaultPassword" = "@Password*123"
}

foreach ($key in $autoLogonSettings.Keys) {
    try {
        setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -regName $key -regValue $autoLogonSettings[$key]
        log success "Successfully set registry key $key"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to set registry key $($key): $message"
        log error "Exiting script"
        exit 1
    }
}

# Disable password logon provider
try {
    setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" -regName "Disabled" -regValue 1
    log success "Password logon provider disabled."
}
catch {
    $message = $_.Exception.Message
    log error "Failed to disable password logon provider: $message"
}

try {
    # Disable DisplayLastUser
    setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -regName "DontDisplayLastUserName" -regValue 1
    log success "DisplayLastUser disabled."
}
catch {
    $message = $_.Exception.Message
    log error "Failed to disable DisplayLastUser: $message"
}


# Set lock screen caption
if ($targetHeaders) {
    $tenant = $config.targetTenant.tenantName
}
else {
    $tenant = $config.sourceTenant.tenantName
}
$lockScreenSettings = @{
    "legalnoticecaption" = "Device Migration in Progress..."
    "legalnoticetext"    = "Your PC is being migrated to the $($tenant) tenant and will automatically reboot in 30 seconds. Please do not power off."
}
foreach ($key in $lockScreenSettings.Keys) {
    try {
        setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -regName $key -regValue $lockScreenSettings[$key]
        log success "Successfully set registry key $key"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to set registry key $($key): $message"
        log error "Exiting script"
        exit 1
    }
}

try {
    # Disable user ESP
    $SkipOOBE = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\" -Recurse | Where-Object { $_.Property -match 'SkipUserStatusPage' }
    if ($SkipOOBE) {
        $Converted = Convert-Path $SkipOOBE.PSPath
        setRegistry -regPath "Registry::$Converted" -regName "SkipUserStatusPage" -regValue 4294967295
        log success "SkipUserStatusPage set successfully."
    }
    else {
        log warning "SkipUserStatusPage not found."
    }
}
catch {
    $message = $_.Exception.Message
    log error "Failed to disable user ESP: $message"
}

# Stop transcript and restart
log info "$($pc.hostname) will reboot in 30 seconds..."
Stop-Transcript
shutdown -r -t 30
