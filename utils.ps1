<#
.SYNOPSIS
    Utility functions for Intune migration process

.DESCRIPTION
    This script contains common utility functions used throughout the Intune migration process,
    including logging, Microsoft Graph authentication, and password generation.

.AUTHOR
    Created for Intune Migration v9

.DATE
    October 27, 2025

.VERSION
    1.0
#>

# Utilities used throughout the migration process

# Log function
function Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateSet('info','warning','error','success')]
        [string]$Type,

        [Parameter(Mandatory, Position=1)]
        [string]$Message
    )

    $date = Get-Date -Format 'yyyy-MM-dd hh:mm:ss tt' # or HH without tt
    $typeFormatted = switch ($Type.ToLower()) {
        'info'    { '[INFO]' }
        'warning' { '[WARNING]' }
        'error'   { '[ERROR]' }
        'success' { '[SUCCESS]' }
    }

    "$date - $typeFormatted - $Message" | Write-Output
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
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
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
        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force | Out-Null
    }
    elseif ($currentValue.$regName -ne $regValue) {
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force | Out-Null
    }
    else {
        return
    }
}

# Invoke Graph rest call
function Invoke-Graph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('GET','POST','PATCH','PUT','DELETE')]
        [string]$Method,

        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [hashtable]$Headers,

        # Pass a JSON object if needed
        [object]$body,

        # Optional status code manual set (default to 2xx)
        [int[]]$OkStatus = @(),

        # If set, converts Body to JSON and Content-type to 'application/json'
        [switch]$AsJson,

        # optional built-in retry for PowerShell 7+ only
        [int]$MaximumRetryCount = 0,
        [int]$RetryIntervalSec = 2
    )

    $status = $null
    $respHeaders = $null

    $irm = @{
        Method                  = $Method
        Uri                     = $Uri
        Headers                 = $Headers
        StatusCodeVariable      = 'status'
        ResponseHeadersVariable = 'respHeaders'
        SkipHttpErrorCheck      = $true
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        if ($AsJson) {
            $irm.ContentType = 'application/json'
            $irm.Body        = $Body | ConvertTo-Json -Depth 20
        } else {
            $irm.Body        = $Body
        }
    }

    if ($MaximumRetryCount -gt 0) {
        $irm.MaximumRetryCount = $MaximumRetryCount
        $irm.RetryIntervalSec  = $RetryIntervalSec
    }

    $response = Invoke-RestMethod @irm

    $code = [int]$status
    $is2xx = ($code -ge 200 -and $code -lt 300)
    $ok = if ($OkStatus.Count) { $OkStatus -contains $code } else { $is2xx }

    $errCode = $null; $errMsg = $null
    if (-not $ok) {
        if ($response -is [string]) {
            try {
                $j = $response | ConvertFrom-Json -ErrorAction Stop
                $errCode = $j.error?.code
                $errMsg  = $j.error?.message
            } catch {}
        } else {
            $errCode = $response.error?.code
            $errMsg  = $response.error?.message
        }
    }

    if (Get-Command log -ErrorAction SilentlyContinue) {
        if ($ok) {
            log success "Graph call OK $($code): $Method $Uri"
        } else {
            $extra = if ($errCode -or $errMsg) { "$errCode - $errMsg" } else { "No Graph error payload" }
            log error "Graph call failed $($code): $Method $Uri :: $extra"
        }
    }

    [pscustomobject]@{
        Success         = $ok
        StatusCode      = $code
        Response        = $response
        ResponseHeaders = $respHeaders
        ErrorCode       = $errCode
        ErrorMessage    = $errMsg
        Uri             = $Uri
        Method          = $Method
    }
}
