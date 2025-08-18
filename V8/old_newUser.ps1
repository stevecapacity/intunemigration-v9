# If target tenant headers exist, get new user object
$newHeaders = ""
if($targetHeaders)
{
    $tenant = $config.targetTenant.tenantName
    log "Target tenant headers found.  Getting new user object from $tenant tenant..."
    $newHeaders = $targetHeaders
}
else
{
    $tenant = $config.sourceTenant.tenantName
    log "Target tenant headers not found.  Getting new user object from $tenant tenant..."
    $newHeaders = $sourceHeaders
}
$fullUPN = $($currentUser.upn)
$split = $fullUPN -split "(@)", 2
$split[0] += $split[1].Substring(0,1)
$split[1] += $split[1].Substring(1)
$userLookup = $split[0]
log "Looking up user where UPN starts with: $userLookup..."
$newUserObject = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=startsWith(userPrincipalName,'$userLookup')" -Headers $newHeaders
# if new user graph request is successful, set new user object
if($null -ne $newUserObject.value)
{
    log "New user found in $tenant tenant."
    $newUser = @{
        upn = $newUserObject.value.userPrincipalName
        entraUserId = $newUserObject.value.id
        SAMName = $newUserObject.value.userPrincipalName.Split("@")[0]
        SID = $newUserObject.value.securityIdentifier
    }
    # Write new user object to registry
    foreach($x in $newUser.Keys)
    {
        $newUserName = "NEW_$($x)"
        $newUserValue = $($newUser[$x])
        if(![string]::IsNullOrEmpty($newUserValue))
        {
            log "Writing $($newUserName) with value $($newUserValue)..."
            try
            {
                reg.exe add $config.regPath /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
                log "Successfully wrote $($newUserName) with value $($newUserValue)."
            }
            catch
            {
                $message = $_.Exception.Message
                log "Failed to write $($newUserName) with value $($newUserValue).  Error: $($message)."
            }
        }
    }
}
else
{
    log "New user not found in $($config.targetTenant.tenantName) tenant.  Prompting user to sign in..."
    
    $installedNuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
    if(-not($installedNuget))
    {
        log "NuGet package provider not installed.  Installing..."
        Install-PackageProvider -Name NuGet -Force
        log "NuGet package provider installed successfully."
    }
    else
    {
        log "NuGet package provider already installed."
    }
    # Check for Az.Accounts module
    $installedAzAccounts = Get-InstalledModule -Name Az.Accounts -ErrorAction SilentlyContinue
    if(-not($installedAzAccounts))
    {
        log "Az.Accounts module not installed.  Installing..."
        Install-Module -Name Az.Accounts -Force
        log "Az.Accounts module installed successfully."
    }
    else
    {
        log "Az.Accounts module already installed."
    }
    $newUserPath = "C:\Users\Public\Documents\newUserInfo.json"
    $timeout = 300
    $checkInterval = 5
    $elapsedTime = 0
    schtasks.exe /create /tn "userFinder" /xml "C:\ProgramData\IntuneMigration\userFinder.xml" /f | Out-Host
    while($elapsedTime -lt $timeout)
    {
        if(Test-Path $newUserPath)
        {
            log "New user found.  Continuing with script..."
            break
        }
        else
        {
            log "New user info not present.  Waiting for user to sign in..."
            Start-Sleep -Seconds $checkInterval
            $elapsedTime += $checkInterval
        }
    }
    if(Test-Path $newUserPath)
    {
        $newUserInfo = Get-Content -Path "C:\Users\Public\Documents\newUserInfo.json" | ConvertFrom-JSON

        $newUser = @{
            entraUserID = $newUserInfo.entraUserId
            SID = $newUserInfo.SID
            SAMName = $newUserInfo.SAMName
            UPN = $newUserInfo.upn
        }
        foreach($x in $newUser.Keys)
        {
            $newUserName = "NEW_$($x)"
            $newUserValue = $($newUser[$x])
            if(![string]::IsNullOrEmpty($newUserValue))
            {
                log "Writing $($newUserName) with value $($newUserValue)..."
                try
                {
                    reg.exe add "HKLM\SOFTWARE\IntuneMigration" /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
                    log "Successfully wrote $($newUserName) with value $($newUserValue)."
                }
                catch
                {
                    $message = $_.Exception.Message
                    log "Failed to write $($newUserName) with value $($newUserValue).  Error: $($message)."
                }
            }
        }
        Write-Host "User found. Continuing with script..."
        Disable-ScheduledTask -TaskName "userFinder"
        Remove-Item -Path $newUserPath -Force -Recurse
    }
    else
    {
        log "New user not found.  Exiting script."
        exitScript -exitCode 4 -functionName "newUser"
    }
} 