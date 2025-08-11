<#
.SYNOPSIS
    Utility functions for Intune migration process

.DESCRIPTION
    This script contains common utility functions used throughout the Intune migration process,
    including logging, Microsoft Graph authentication, and password generation.

.AUTHOR
    Created for Intune Migration v9

.DATE
    August 8, 2025

.VERSION
    1.0
#>

# Utilities used throughout the migration process

# Log function
function log {
    Param(
        [string]$message,
        [string]$type
    )
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    $typeFormatted = switch ($type) {
        "info" { "[INFO]" }
        "error" { "[ERROR]" }
        "warning" { "[WARNING]" }
        "success" { "[SUCCESS]" }
        Default { "[$($type.ToUpper())]" }
    }
    $output = "$($date) - $typeFormatted - $($message)"
    Write-Output $output
}

# Graph authenticate
function msGraphAuthenticate() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$tenantName,
        [Parameter(Mandatory = $true)]
        [string]$clientId,
        [Parameter(Mandatory = $true)]
        [string]$clientSecret
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencdoded")
    $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body += -join ("&client_id=", $clientId, "&client_secret=", $clientSecret)
    $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method Post -Headers $headers -Body $body

    $token = -join ("Bearer ", $response.access_token)

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")
    $headers = @{'Authorization' = "$($token)" }
    return $headers
}

# Generate password
function generatePassword() {
    Param(
        [int]$length = 12
    )
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',<.>/?"
    $securePassword = New-Object -TypeName System.Security.SecureString
    1..$length | ForEach-Object {
        $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
        $securePassword.AppendChar($random)
    }
    return $securePassword
}

# Set registry
function setRegistry() {
    Param(
        [string]$regPath,
        [string]$regName,
        [string]$regType,
        [object]$regValue
    )

    # Check if the path exists
    if (-not (Test-Path $regPath)) {
        log warning "Registry path $regPath does not exist, creating it..."
        New-Item -Path $regPath -Force | Out-Null
    }

    # Check current value
    $currentValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

    if ($null -eq $currentValue) {
        log warning "$regName not found, setting to 1..."
        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force | Out-Null
        log success "Successfully set $regName to 1"
    }
    elseif ($currentValue.$regName -ne $regValue) {
        log warning "$regName is currently set to $($currentValue.$regName), changing to $regValue..."
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force | Out-Null
        log success "Successfully updated $regName to $regValue"
    }
    else {
        log success "$regName is already set to $regValue"
    }
}


