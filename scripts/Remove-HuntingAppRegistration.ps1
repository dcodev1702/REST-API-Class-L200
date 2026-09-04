<#
.SYNOPSIS
    Removes the Entra ID app registration and local certificate created for the hunting demos, using the exact
    identifiers recorded in HuntingDemo.settings.json.

.DESCRIPTION
    Companion teardown for New-HuntingAppRegistration.ps1 in the session "REST APIs, JSON & the Microsoft Graph
    Security API". The settings JSON is the source of truth for the tenant, application, service principal,
    endpoints, and local certificate. Its contents are never echoed, and a legacy clientSecret property is ignored.

    The script performs one confirmed cleanup operation:

      1. Read and validate HuntingDemo.settings.json, including tenant/client/object correlation GUIDs.
      2. Sign in (Connect-MgGraph) with Application.ReadWrite.All in the recorded tenant and cloud.
      3. GET    /applications and /servicePrincipals               -> resolve the recorded directory objects.
      4. POST   /applications/{id}/removePassword                  -> revoke every password credential on the app.
      5. PATCH  /applications/{id}                                 -> remove every registered certificate public key.
      6. Remove the correlated local private-key certificate from Cert:\CurrentUser\My.
      7. DELETE /servicePrincipals/{id}                             -> remove the enterprise app and its consent grants.
      8. DELETE /applications/{id}                                 -> delete the app registration (recoverable for 30 days).
      9. Delete HuntingDemo.settings.json and clear HUNT_CLIENT_SECRET from the current process.

    Cleanup is idempotent: missing credentials and objects are reported as already absent. If a later step fails,
    the settings file remains available so the same command can safely resume. Use -WhatIf to inspect the exact
    correlated targets without changing the certificate store or directory.

.PARAMETER SettingsFile
    Settings JSON written by New-HuntingAppRegistration.ps1. Default: HuntingDemo.settings.json next to this script.

.EXAMPLE
    .\scripts\Remove-HuntingAppRegistration.ps1 -WhatIf
.EXAMPLE
    .\scripts\Remove-HuntingAppRegistration.ps1
.EXAMPLE
    .\scripts\Remove-HuntingAppRegistration.ps1 -Confirm:$false

.LINK
    https://learn.microsoft.com/graph/api/application-removepassword
.LINK
    https://learn.microsoft.com/graph/api/application-update
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-delete
.LINK
    https://learn.microsoft.com/graph/api/application-delete
#>
#Requires -Version 7.3
#Requires -Modules Microsoft.Graph.Authentication
# Author: DCODEV1702 & GHCP (ChatGPT 5.6 Sol)
# Date: 2026-09-04
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $SettingsFile = (Join-Path $PSScriptRoot 'HuntingDemo.settings.json')
)

$ErrorActionPreference = 'Stop'

function Invoke-Graph {
    # Thin wrapper so every call prints the verb + URI (the REST anatomy) before it runs.
    param([string] $Method, [string] $Uri, $Body)
    Write-Host ("  {0,-6} {1}" -f $Method.ToUpper(), $Uri) -ForegroundColor DarkGray
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}

function ConvertTo-RequiredGuid {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter(Mandatory)]
        [string] $PropertyName,

        [switch] $Optional
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ($Optional) { return $null }
        throw "Settings property '$PropertyName' is required."
    }

    $parsedGuid = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref] $parsedGuid)) {
        throw "Settings property '$PropertyName' is not a valid GUID."
    }
    $parsedGuid.ToString()
}

# ------------------------------------------------------------------------------------------------
# 1. Settings are the cleanup manifest. Validate every value used to select or address a resource.
# ------------------------------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $SettingsFile -PathType Leaf)) {
    throw "Settings file not found: $SettingsFile"
}

try {
    $settings = Get-Content -LiteralPath $SettingsFile -Raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "Could not read settings JSON '$SettingsFile': $($_.Exception.Message)"
}

$tenantId = ConvertTo-RequiredGuid -Value $settings.tenantId -PropertyName 'tenantId'
$clientId = ConvertTo-RequiredGuid -Value $settings.clientId -PropertyName 'clientId'
$appObjectId = ConvertTo-RequiredGuid -Value $settings.appObjectId -PropertyName 'appObjectId' -Optional
$servicePrincipalId = ConvertTo-RequiredGuid -Value $settings.servicePrincipalId -PropertyName 'servicePrincipalId' -Optional
$recordedSecretKeyId = ConvertTo-RequiredGuid -Value $settings.secretKeyId -PropertyName 'secretKeyId' -Optional
$recordedCertificateKeyId = ConvertTo-RequiredGuid -Value $settings.certificateKeyId -PropertyName 'certificateKeyId' -Optional
$displayName = if ([string]::IsNullOrWhiteSpace($settings.displayName)) { $clientId } else { [string] $settings.displayName }

$mgEnvironment = if (-not [string]::IsNullOrWhiteSpace($settings.mgEnvironment)) {
    [string] $settings.mgEnvironment
}
elseif ($settings.environment -eq 'AzureGov') { 'USGov' }
else { 'Global' }

$allowedGraphHosts = @{
    Global   = 'https://graph.microsoft.com'
    USGov    = 'https://graph.microsoft.us'
    USGovDoD = 'https://dod-graph.microsoft.us'
}
if (-not $allowedGraphHosts.ContainsKey($mgEnvironment)) {
    throw "Unsupported mgEnvironment '$mgEnvironment' in settings. Expected Global, USGov, or USGovDoD."
}

$graphHost = if ([string]::IsNullOrWhiteSpace($settings.graphHost)) {
    $allowedGraphHosts[$mgEnvironment]
}
else { ([string] $settings.graphHost).TrimEnd('/') }
if ($graphHost -ne $allowedGraphHosts[$mgEnvironment]) {
    throw "Settings graphHost '$graphHost' does not match mgEnvironment '$mgEnvironment'."
}

$certificateStore = if ([string]::IsNullOrWhiteSpace($settings.certificateStore)) {
    'Cert:\CurrentUser\My'
}
else { ([string] $settings.certificateStore).TrimEnd('\') }
if ($certificateStore -ne 'Cert:\CurrentUser\My') {
    throw "Unsupported certificateStore '$certificateStore'. Expected Cert:\CurrentUser\My."
}

$certificateThumbprint = ([string] $settings.certificateThumbprint).Trim()
if ($certificateThumbprint -and $certificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
    throw "Settings property 'certificateThumbprint' is not a valid SHA-1 certificate thumbprint."
}
$certificateName = if (-not [string]::IsNullOrWhiteSpace($settings.certificateName)) {
    [string] $settings.certificateName
}
elseif (-not [string]::IsNullOrWhiteSpace($settings.certificateFriendlyName)) {
    [string] $settings.certificateFriendlyName
}
else { 'not recorded' }
$certificatePath = if ($certificateThumbprint) {
    Join-Path -Path $certificateStore -ChildPath $certificateThumbprint
}
else { "$certificateStore\<thumbprint not recorded>" }

if ($settings.PSObject.Properties.Name -contains 'clientSecret') {
    Write-Warning 'The settings file contains a legacy plaintext clientSecret property. Its value will not be displayed or used; successful teardown deletes the file.'
}

# ------------------------------------------------------------------------------------------------
# 2. Sign in to the recorded tenant/cloud. Application.ReadWrite.All covers credentials and both objects.
# ------------------------------------------------------------------------------------------------
Write-Host "`nSettings   : $SettingsFile" -ForegroundColor Cyan
Write-Host "App        : $displayName" -ForegroundColor Cyan
Write-Host "Tenant     : $tenantId   Client ID : $clientId" -ForegroundColor DarkGray
Write-Host "Graph host : $graphHost   Environment : $mgEnvironment`n" -ForegroundColor DarkGray

Set-MgGraphOption -DisableLoginByWAM $false
Connect-MgGraph -TenantId $tenantId -Environment $mgEnvironment -Scopes 'Application.ReadWrite.All' -NoWelcome
$ctx = Get-MgContext
if ($ctx.TenantId -ne $tenantId) {
    throw "Signed in to tenant '$($ctx.TenantId)', but settings require tenant '$tenantId'."
}
$g = "$graphHost/v1.0"
Write-Host "Signed in as $($ctx.Account) in tenant $($ctx.TenantId)`n" -ForegroundColor Green

# ------------------------------------------------------------------------------------------------
# 3. Resolve by the immutable client ID, then cross-check the recorded object IDs before deletion.
# ------------------------------------------------------------------------------------------------
Write-Host 'Step 3  Resolve the recorded app registration and service principal' -ForegroundColor Cyan
$app = (Invoke-Graph -Method GET -Uri "$g/applications?`$filter=appId%20eq%20'$clientId'&`$select=id,appId,displayName,passwordCredentials,keyCredentials").value |
    Select-Object -First 1
if ($app -and $appObjectId -and $app.id -ne $appObjectId) {
    throw "App object ID mismatch. Settings record '$appObjectId'; Graph returned '$($app.id)' for client ID '$clientId'."
}
if ($app) {
    Write-Host "        found app object $($app.id)" -ForegroundColor Green
    $appObjectId = $app.id
    $displayName = $app.displayName
}
else { Write-Host '        app registration already absent' -ForegroundColor Yellow }

$spCandidates = @((Invoke-Graph -Method GET -Uri "$g/servicePrincipals?`$filter=appId%20eq%20'$clientId'&`$select=id,appId,displayName").value)
$sp = if ($servicePrincipalId) {
    $spCandidates | Where-Object id -eq $servicePrincipalId | Select-Object -First 1
}
else { $spCandidates | Select-Object -First 1 }
if ($servicePrincipalId -and $spCandidates.Count -gt 0 -and -not $sp) {
    throw "Service principal ID mismatch. Settings record '$servicePrincipalId', but that object was not returned for client ID '$clientId'."
}
if ($sp) {
    Write-Host "        found service principal $($sp.id)" -ForegroundColor Green
    $servicePrincipalId = $sp.id
}
else { Write-Host '        service principal already absent' -ForegroundColor Yellow }

$passwordCredentials = @($app.passwordCredentials)
$keyCredentials = @($app.keyCredentials)
$localCertificate = $null
if ($certificateThumbprint) {
    $localCertificate = Get-Item -LiteralPath $certificatePath -ErrorAction SilentlyContinue
}

Write-Host "`nCleanup manifest" -ForegroundColor Cyan
Write-Host "  Password credentials : $($passwordCredentials.Count)$(if ($recordedSecretKeyId) { " (recorded key $recordedSecretKeyId)" })"
Write-Host "  Certificate keys     : $($keyCredentials.Count)$(if ($recordedCertificateKeyId) { " (recorded key $recordedCertificateKeyId)" })"
Write-Host "  Certificate name     : $certificateName"
Write-Host "  Certificate location : $certificatePath"
Write-Host "  Local certificate    : $(if ($localCertificate) { $localCertificate.Thumbprint } else { 'already absent' })"
Write-Host "  Service principal    : $(if ($sp) { $sp.id } else { 'already absent' })"
Write-Host "  App registration     : $(if ($app) { $app.id } else { 'already absent' })"

$target = "'$displayName' ($clientId) in tenant $tenantId"
$action = 'Revoke all secrets and certificate keys, remove the local private key, delete the service principal and app registration, then delete the settings file'
if (-not $PSCmdlet.ShouldProcess($target, $action)) {
    return [pscustomobject]@{
        Mode                    = 'Preview'
        DisplayName             = $displayName
        TenantId                = $tenantId
        ClientId                = $clientId
        PasswordCredentials     = $passwordCredentials.Count
        ApplicationCertificates = $keyCredentials.Count
        LocalCertificateFound   = [bool] $localCertificate
        ServicePrincipalFound   = [bool] $sp
        ApplicationFound        = [bool] $app
        SettingsFile            = $SettingsFile
    }
}

# ------------------------------------------------------------------------------------------------
# 4. Revoke every app secret. Reused demo apps can have more than the one key ID in the latest settings file.
# ------------------------------------------------------------------------------------------------
$passwordsRemoved = 0
if ($app) {
    Write-Host "`nStep 4  Revoke $($passwordCredentials.Count) client secret(s)" -ForegroundColor Cyan
    foreach ($credential in $passwordCredentials) {
        Invoke-Graph -Method POST -Uri "$g/applications/$appObjectId/removePassword" -Body @{ keyId = $credential.keyId } | Out-Null
        $passwordsRemoved++
        Write-Host "        removed password key $($credential.keyId)" -ForegroundColor Green
    }
    if ($passwordCredentials.Count -eq 0) { Write-Host '        already absent' -ForegroundColor DarkGray }
}

# ------------------------------------------------------------------------------------------------
# 5. Remove every uploaded public certificate. The local private key is removed separately in step 6.
# ------------------------------------------------------------------------------------------------
$applicationCertificatesRemoved = 0
if ($app) {
    Write-Host "Step 5  Remove $($keyCredentials.Count) registered certificate key(s)" -ForegroundColor Cyan
    if ($keyCredentials.Count -gt 0) {
        Invoke-Graph -Method PATCH -Uri "$g/applications/$appObjectId" -Body @{ keyCredentials = @() } | Out-Null
        $applicationCertificatesRemoved = $keyCredentials.Count
        Write-Host '        all registered certificate keys removed' -ForegroundColor Green
    }
    else { Write-Host '        already absent' -ForegroundColor DarkGray }
}

# ------------------------------------------------------------------------------------------------
# 6. Delete only the local certificate identified by the recorded SHA-1 thumbprint.
# ------------------------------------------------------------------------------------------------
Write-Host 'Step 6  Remove the correlated local training certificate and private key' -ForegroundColor Cyan
$localCertificatesRemoved = 0
if ($localCertificate) {
    Remove-Item -LiteralPath $localCertificate.PSPath -DeleteKey -Force
    $localCertificatesRemoved = 1
    Write-Host "        removed $($localCertificate.Thumbprint) from $certificateStore" -ForegroundColor Green
}
else { Write-Host '        already absent' -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------------------------
# 7-8. Delete the enterprise app first (consent lives there), then the app registration.
# ------------------------------------------------------------------------------------------------
$servicePrincipalRemoved = $false
Write-Host 'Step 7  Delete the service principal (enterprise application and consent grants)' -ForegroundColor Cyan
if ($sp) {
    Invoke-Graph -Method DELETE -Uri "$g/servicePrincipals/$servicePrincipalId" | Out-Null
    $servicePrincipalRemoved = $true
    Write-Host "        deleted $servicePrincipalId" -ForegroundColor Green
}
else { Write-Host '        already absent' -ForegroundColor DarkGray }

$applicationRemoved = $false
Write-Host 'Step 8  Delete the app registration' -ForegroundColor Cyan
if ($app) {
    Invoke-Graph -Method DELETE -Uri "$g/applications/$appObjectId" | Out-Null
    $applicationRemoved = $true
    Write-Host "        deleted $appObjectId (recoverable for 30 days)" -ForegroundColor Green
}
else { Write-Host '        already absent' -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------------------------
# 9. Remove the manifest only after every requested directory/local operation succeeds.
# ------------------------------------------------------------------------------------------------
Write-Host 'Step 9  Remove local secret state and cleanup manifest' -ForegroundColor Cyan
$environmentSecretCleared = Test-Path -LiteralPath 'Env:\HUNT_CLIENT_SECRET'
if ($environmentSecretCleared) { Remove-Item -LiteralPath 'Env:\HUNT_CLIENT_SECRET' -Force }
Remove-Item -LiteralPath $SettingsFile -Force
Write-Host "        deleted $SettingsFile" -ForegroundColor Green
if ($environmentSecretCleared) { Write-Host '        cleared HUNT_CLIENT_SECRET from the current process' -ForegroundColor Green }

Write-Host "`nTeardown complete for '$displayName'." -ForegroundColor Green
[pscustomobject]@{
    Mode                           = 'Removed'
    DisplayName                    = $displayName
    TenantId                       = $tenantId
    ClientId                       = $clientId
    PasswordsRemoved               = $passwordsRemoved
    ApplicationCertificatesRemoved = $applicationCertificatesRemoved
    LocalCertificatesRemoved       = $localCertificatesRemoved
    ServicePrincipalRemoved        = $servicePrincipalRemoved
    ApplicationRemoved             = $applicationRemoved
    EnvironmentSecretCleared       = $environmentSecretCleared
    SettingsFileRemoved            = $true
}