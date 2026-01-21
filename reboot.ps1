
<#
    .SYNOPSIS
        Changes user SID and profile ownership to the new user, then reboots the machine.

    .DESCRIPTION
        This script changes ownership of the original user profile to the destination user and reboots the machine. It is executed by the 'reboot' scheduled task.

    .EXAMPLE
        .\reboot.ps1

    .AUTHOR
        Steve Weiner

    .CONTRIBUTORS
        Logan Lautt
#>

$ErrorActionPreference = "SilentlyContinue"

# import functions
. "$($PSScriptRoot)\utils.ps1"


# Import config settings from JSON file
$config = Get-Content "C:\ProgramData\IntuneMigration\config.json" | ConvertFrom-Json

# Start Transcript
Start-Transcript -Path "$($config.logPath)\reboot.log" -Verbose
log info "Starting Reboot.ps1..."

# Initialize script
$localPath = $config.localPath
if (!(Test-Path $localPath)) {
    log info "$($localPath) does not exist.  Creating..."
    mkdir $localPath
}
else {
    log info "$($localPath) already exists."
}

# Check context
$context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
log info "Running as $($context)"
$systemSIDs = @("S-1-5-18") # SID for NT AUTHORITY\SYSTEM
$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

if ($currentSID -notin $systemSIDs) {
    log error "Script must be run in system context. Exiting..."
    exit 1
}
# disable reboot task
log info "Disabling reboot task..."
Disable-ScheduledTask -TaskName "Reboot"
log info "Reboot task disabled"

# disable auto logon
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Verbose
log info "Auto logon disabled."


# Retrieve variables from registry
log info "Retrieving variables from registry..."
$regKey = "Registry::$($config.regPath)"
$values = Get-ItemProperty -Path $regKey
$values.PSObject.Properties | ForEach-Object {
    $name = $_.Name
    $value = $_.Value
    if (![string]::IsNullOrEmpty($value)) {
        log info "Retrieved $($name): $value"
        New-Variable -Name $name -Value $value -Force
    }
    else {
        log error "Error retrieving $name"
    }
}

if ($OLD_SID -eq $NEW_SID) {
    log info "Old SID $($OLD_SID) and new SID $($NEW_SID) are the same. Skipping new profile creation."
}
else {
    # Remove aadBrokerPlugin from profile
    $aadBrokerPath = (Get-ChildItem -Path "$($OLD_profilePath)\AppData\Local\Packages" -Recurse | Where-Object { $_.Name -match "Microsoft.AAD.BrokerPlugin_*" }).FullName
    if ($aadBrokerPath) {
        log info "Removing aadBrokerPlugin from profile..."
        Remove-Item -Path $aadBrokerPath -Recurse -Force
        log success "aadBrokerPlugin removed"
    }
    else {
        log info "aadBrokerPlugin not found"
    }

    # Create new user profile
    log info "Creating $($NEW_SAMName) profile..."
    Add-Type -TypeDefinition @"
using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
namespace UserProfile {
    public static class Class {
        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int CreateProfile(
            [MarshalAs(UnmanagedType.LPWStr)] String pszUserSid,
            [MarshalAs(UnmanagedType.LPWStr)] String pszUserName,
            [Out][MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszProfilePath,
            uint cchProfilePath
        );
    }
}
"@

    $sb = New-Object System.Text.StringBuilder(260)
    $pathLen = $sb.Capacity

    try {
        $CreateProfileReturn = [UserProfile.Class]::CreateProfile($NEW_SID, $NEW_SAMName, $sb, $pathLen)
    }
    catch {
        Write-Error $_.Exception.Message
    }

    switch ($CreateProfileReturn) {
        0 {
            Write-Output "User profile created successfully at path: $($sb.ToString())"
        }
        -2147024713 {
            Write-Output "User profile already exists."
        }
        default {
            throw "An error occurred when creating the user profile: $CreateProfileReturn"
        }
    }

    # Delete New profile
    log info "Deleting new profile..."
    $newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $NEW_SID }
    try {
        Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null    
        log info "New profile deleted."
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to delete new profile: $message"
        log error "Exiting script..."
        shutdown -r -t 05
    }

    # Change ownership of user profile
    log info "Changing ownership of user profile..."
    $currentProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $OLD_SID }
    $changes = @{
        NewOwnerSID = $NEW_SID
        Flags       = 0
    }

    try {
        $currentProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changes | Out-Null
        log success "User profile ownership changed."
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to change user profile ownership: $message"
        log error "Exiting script..."
        shutdown -r -t 05
    }

    # Cleanup logon cache
    function cleanupLogonCache() {
        Param(
            [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
            [string]$oldUPN = $OLD_UPN
        )
        log info "Cleaning up logon cache..."
        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach ($GUID in $logonCacheGUID) {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if (!($subKeys)) {
                log info "No subkeys found for $GUID"
                continue
            }
            else {
                $subKeys = $subKeys.trim('{}')
                foreach ($subKey in $subKeys) {
                    if ($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name") {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if (!($subFolders)) {
                            log warning "Error - no sub folders found for $subKey"
                            continue
                        }
                        else {
                            $subFolders = $subFolders.trim('{}')
                            foreach ($subFolder in $subFolders) {
                                $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                                if ($cacheUsername -eq $oldUserName) {
                                    Remove-Item -Path "$logonCache\$GUID\$subKey\$subFolder" -Recurse -Force
                                    log success "Registry key deleted: $logonCache\$GUID\$subKey\$subFolder"
                                    continue                                       
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # run cleanupLogonCache
    log info "Running cleanupLogonCache..."
    try {
        cleanupLogonCache
        log success "cleanupLogonCache completed"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to run cleanupLogonCache: $message"
        log error "Exiting script..."
    }

    # cleanup identity store cache
    function cleanupIdentityStore() {
        Param(
            [string]$idCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache",
            [string]$oldUserName = $OLD_UPN
        )
        log info "Cleaning up identity store cache..."
        $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach ($key in $idCacheKeys) {
            $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
            if (!($subKeys)) {
                log info "No keys listed under '$idCache\$key' - skipping..."
                continue
            }
            else {
                $subKeys = $subKeys.trim('{}')
                foreach ($subKey in $subKeys) {
                    $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if (!($subFolders)) {
                        log info "No subfolders detected for $subkey- skipping..."
                        continue
                    }
                    else {
                        $subFolders = $subFolders.trim('{}')
                        foreach ($subFolder in $subFolders) {
                            $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                            if ($idCacheUsername -eq $oldUserName) {
                                Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                                log info "Registry path deleted: $idCache\$key\$subKey\$subFolder"
                                continue
                            }
                        }
                    }
                }
            }
        }
    }

    # run cleanup identity store cache if not domain joined
    if ($OLD_domainJoined -eq "NO") {
        log info "Running cleanupIdentityStore..."
        try {
            cleanupIdentityStore
            log success "cleanupIdentityStore completed"
        }
        catch {
            $message = $_.Exception.Message
            log error "Failed to run cleanupIdentityStore: $message"
            log error "Exiting script..."
        }
    }
    else {
        log info "Machine is domain joined - skipping cleanupIdentityStore."
    }

    # update samname in identityStore LogonCache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
    function updateSamNameLogonCache() {
        Param(
            [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
            [string]$targetSAMName = $OLD_SAMName
        )

        if ($NEW_SAMName -like "$($OLD_SAMName)_*" -or $NEW_SAMName -like "$($OLD_SAMName).*") {
            log info "New user is $NEW_SAMName, which is the same as $OLD_SAMName with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

            $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
            foreach ($GUID in $logonCacheGUID) {
                $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if (!($subKeys)) {
                    log warning "No subkeys found for $GUID"
                    continue
                }
                else {
                    $subKeys = $subKeys.trim('{}')
                    foreach ($subKey in $subKeys) {
                        if ($subKey -eq "Name2Sid") {
                            $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                            if (!($subFolders)) {
                                log warning "Error - no sub folders found for $subKey"
                                continue
                            }
                            else {
                                $subFolders = $subFolders.trim('{}')
                                foreach ($subFolder in $subFolders) {
                                    $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                    if ($detectedUserSID -eq $NEW_SID) {
                                        Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                        log info "Attempted to update SAMName value (in Name2Sid registry folder) to '$targetSAMName'."
                                        continue                                       
                                    }
                                    else {
                                        log info "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                    }
                                }
                            }
                        }
                        elseif ($subKey -eq "SAM_Name") {
                            $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                            if (!($subFolders)) {
                                log warning "Error - no sub folders found for $subKey"
                                continue
                            }
                            else {
                                $subFolders = $subFolders.trim('{}')
                                foreach ($subFolder in $subFolders) {
                                    $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                    if ($detectedUserSID -eq $NEW_SID) {
                                        Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $targetSAMName -Force
                                        log info "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$targetSAMName'."
                                        continue                                       
                                    }
                                    else {
                                        log info "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                    }
                                }
                            }
                        }
                        elseif ($subKey -eq "Sid2Name") {
                            $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                            if (!($subFolders)) {
                                log warning "Error - no sub folders found for $subKey"
                                continue
                            }
                            else {
                                $subFolders = $subFolders.trim('{}')
                                foreach ($subFolder in $subFolders) {
                                    if ($subFolder -eq $NEW_SID) {
                                        Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                        log info "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$targetSAMName'."
                                        continue                                       
                                    }
                                    else {
                                        log info "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            log info "New username is $NEW_SAMName, which does not match older username ($OLD_SAMName) with _##### appended to end. SamName LogonCache registry will not be updated."
        }
    }

    # run updateSamNameLogonCache
    log info "Running updateSamNameLogonCache..."
    try {
        updateSamNameLogonCache
        log success "updateSamNameLogonCache completed"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to run updateSamNameLogonCache: $message"
        log error "Exiting script..."
    }

    # update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
    function updateSamNameIdentityStore() {
        Param(
            [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
            [string]$targetSAMName = $OLD_SAMName
        )
        if ($NEW_SAMName -like "$($OLD_SAMName)_*") {
            log info "Cleaning up identity store cache..."
            $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
            foreach ($key in $idCacheKeys) {
                $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
                if (!($subKeys)) {
                    log warning "No keys listed under '$idCache\$key' - skipping..."
                    continue
                }
                else {
                    $subKeys = $subKeys.trim('{}')
                    foreach ($subKey in $subKeys) {
                        $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if (!($subFolders)) {
                            log info "No subfolders detected for $subkey- skipping..."
                            continue
                        }
                        else {
                            $subFolders = $subFolders.trim('{}')
                            foreach ($subFolder in $subFolders) {
                                if ($subFolder -eq $NEW_SID) {
                                    Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log info "Attempted to update SAMName value to $targetSAMName."
                                }
                                else {
                                    log info "Skipping different user SID ($subFolder) in $subKey registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            log info "New username is $NEW_SAMName, which does not match older username ($OLD_SAMName) with _##### appended to end. SamName IdentityStore registry will not be updated."
        }
    }

    # run updateSamNameIdentityStore if not domain joined
    if ($OLD_domainJoined -eq "NO") {
        log info "Running updateSamNameIdentityStore..."
        try {
            updateSamNameIdentityStore
            log success "updateSamNameIdentityStore completed"
        }
        catch {
            $message = $_.Exception.Message
            log error "Failed to run updateSamNameIdentityStore: $message"
        }
    }
    else {
        log info "Machine is domain joined - skipping updateSamNameIdentityStore."
    }
}


# enable logon provider
log info "Enabling logon provider..."
try {
    setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" -regName "Disabled" -regValue 0
    log success "Logon provider enabled successfully."
}
catch {
    $message = $_.Exception.Message
    log error "Failed to enable logon provider..."
    log error "Exiting script"
}


# set lock screen caption
if ($config.targetTenant.tenantName) {
    $tenant = $config.targetTenant.tenantName
}
else {
    $tenant = $config.sourceTenant.tenantName
}

Start-Sleep -Seconds 30

$lockScreenSettings = @{
    "legalnoticecaption" = "Welcome to $($tenant)"
    "legalnoticetext"    = "Please log in with your new email address"
}
foreach ($key in $lockScreenSettings.Keys) {
    try {
        setRegistry -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -regName $key -regValue $lockScreenSettings[$key]
        log success "Successfully set registry key $key"
    }
    catch {
        $message = $_.Exception.Message
        log error "Failed to set registry key $($key): $message"
        log warning "Lock screen message may be compromised"
    }
}


log info "Reboot.ps1 complete"
Stop-Transcript
shutdown -r -t 00


