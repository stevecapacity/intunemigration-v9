# Import utils module
. "$($PSScriptRoot)\utils.ps1"

$ErrorActionPreference = "SilentlyContinue"

# Import configuration file
$config = Get-Content ".\config.json" | ConvertFrom-Json
log info "Importing config file"

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
$context = whoami
log info "Running as $($context)"
if ($context -ne "NT AUTHORITY\SYSTEM") {
    log error "Script must be run in system context. Exiting..."
    exit 1
}

# Copy package files to local path
log info "Copying package files to local path"
$sourcePath = "$PSScriptRoot\PackageFiles"
$files = Get-ChildItem -Path $sourcePath -Recurse
$destination = $localPath
foreach ($file in $files) {
    log info "Copying $($file.FullName) to $destination..."
    try {
        Copy-Item -Path $file.FullName -Destination $destination -Recurse -Force
        log success "Coppied $($file.FullName) to $destination"
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
        log info "Authenticate to destination tenant $($config.targetTenant.tenantName)..."
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

# Try to get new user info from target tenant
$newHeaders = ""
if ($targetHeaders) {
    $tenant = $config.targetTenant.tenantName
    log info "Target tenant headers found. Getting new user object from $tenant tenant..."
    $newHeaders = $targetHeaders
}
else {
    $tenant = $config.sourceTenant.tenantName
    log info "Target tenant headers not found. Getting new user object from $tenant tenant..."
    $newHeaders = $sourceHeaders
}

# Use the username part of UPN for lookup (standard approach)
$fullUPN = $($currentUser.upn)
if ($null -eq $fullUPN -or $fullUPN -eq "") {
    log error "Current user UPN is null or empty. Cannot perform user lookup."
    exit 1
}
$userLookup = $fullUPN.Split("@")[0]
log info "Looking up user where UPN starts with: $userLookup..."

# Get new user object from graph
$userURI = "https://graph.microsoft.com/beta/users?`$filter=startsWith(userPrincipalName, '$userLookup')"
$response = Invoke-MgGraphRequest -Method GET -Uri $userURI
$newUserObject = $response.value

# if new user graph request is successful, set new user object
if ($null -ne $newUserObject) {
    log info "New user found in $tenant tenant"
    $newUser = @{
        upn         = $newUserObject.userPrincipalName
        entraUserID = $newUserObject.id
        SAMName     = $newUserObject.userPrincipalName.Split("@")[0]
        SID         = $newUserObject.securityIdentifier
    }
    # Write new user values to registry
    foreach ($x in $newUser.keys) {
        $newUserName = "NEW_$($x)"
        $newUserValue = $($newUser[$x])
        if ([string]::IsNullOrEmpty($newUserValue)) {
            log warning "$($newUserName) is null"
            log warning "Skipping registry write for $($newUserName)"
        }
        else {
            log info "Writing $($newUserName) to registry with value $($newUserValue)..."
            try {
                reg.exe add $($config.regPath) /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
                log success "Successfully wrote $($newUserName) to registry with value $($newUserValue)."
            }
            catch {
                $message = $_.Exception.Message
                log error "Failed to write $($newUserName) to registry: $message"
            }
        }
    }
}
else {
    log info "New user not found in $tenant tenant. Prompting for user sign in..."

    # Check for NuGet package provider
    $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
    if (-not($nuget)) {
        log info "Nuget package provider not found- installing..."
        try {
            Install-PackageProvider -Name NuGet -Confirm:$false -Force
            log success "Nuget installed successfully."
        }
        catch {
            $message = $_.Exception.Message
            log error "Failed to install Nuget: $message"
            log error "Exiting script"
            exit 1
        }
    }
    else {
        log info "Nuget package provider found."
    }

    # Check for required modules
    $modules = ("Az.Accounts", "RunAsUser")
    foreach ($module in $modules) {
        $installedModule = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue
        if (-not($installedModule)) {
            log info "$module module not found - installing..."
            if ($module -eq "Az.Accounts") {
                log info "Module is $($module): setting required version to 4.2.0..."
                $version = "4.2.0"
                try {
                    Install-Module -Name $module -RequiredVersion $version -Force
                    log success "$module installed successfully"
                }
                catch {
                    $message = $_.Exception.Message
                    log error "Failed to install module $($module): $message"
                    log error "Exiting"
                    exit 1
                }
            }
            else {
                try {
                    Install-Module -Name $module -Force
                    log success "$module installed successfully"
                }
                catch {
                    $message = $_.Exception.Message
                    log error "Failed to install $($module): $message"
                    log error "Exiting script"
                    exit 1
                }
            }
        }
        elseif ($module -eq "Az.Accounts" -and $installedModule.Version -ge "5.0.0") {
            log info "Uninstalling newer version of $module..."
            $version = "4.2.0"
            try {
                Uninstall-Module -Name $module -AllVersions -Force
                Install-Module -Name $module -RequiredVersion $version -Force
                log success "Successfully replaced $module with version $version"
            }
            catch {
                $message = $_.Exception.Message
                log error "Failed to downgrade $($module) to version $($version): $message"
                log error "Exiting script"
                exit 1
            }
        }
        else {
            log info "$module already installed"
        } 
    }

    $scriptBlock = {
        Import-Module Az.Accounts

        # Get token from OAuth
        Clear-AzContext -Force
        Update-AzConfig -EnableLoginByWam $false -LoginExperienceV2 Off
        Connect-AzAccount
        $theToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"

        # Get token
        $token = -join("Bearer ", $theToken.Token)

        # Reinstantiate headers
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.add("Authorization", $token)
        $headers.Add("Content-Type", "application/json")

        # Get new user object
        $newUserObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/me" -Headers $headers

        # assemble ne wuser object
        $newUser = @{
            upn = $newUserObject.userPrincipalName
            entraUserId = $newUserOb.id
            SAMName = $newUserObject.userPrincipalName.Split("@")[0]
            SID = $newUserObject.securityIdentifier
        } | ConvertTo-Json

        $newUser | Out-File "C:\temp\newUserInfo.json"
    }
    $newUserPath= = "C:\temp\newUserInfo.json"
    $timeout = 300
    $checkInterval = 5
    $elapsedTime = 0
    Invoke-AsCurrentUser -ScriptBlock $scriptBlock -UseWindowsPowerShell
    while($elapsedTime -lt $timeout){
        if(Test-Past $newUserPath){
            log "New user found. Continue"
        }
    }
}