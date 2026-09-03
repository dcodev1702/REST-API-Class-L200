#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Creates (or reuses) the Entra ID app registration used by the AppOnly demo - programmatically, through
    Microsoft Graph REST calls - including the ThreatHunting.Read.All application permission, tenant-wide
    admin consent, and a client secret valid for 12 months.

.DESCRIPTION
    Companion to Invoke-HuntingQuery.ps1 for the session "REST APIs, JSON & the Microsoft Graph Security API".
    Every step is a Microsoft Graph REST call issued with Invoke-MgGraphRequest, so the class sees that the
    Entra admin center is just another REST client:

      1. Sign in (Connect-MgGraph) with the delegated scopes needed to manage apps and grant consent.
      2. GET  /servicePrincipals?$filter=appId eq '<Microsoft Graph>'  -> look up the ThreatHunting.Read.All
         app role id (application permission) instead of hard-coding a GUID.
      3. POST /applications                                           -> the app registration (single tenant)
         with requiredResourceAccess = Microsoft Graph / ThreatHunting.Read.All (Role).
      4. POST /applications/{id}/addPassword                          -> client secret, endDateTime = now + 12 months.
      5. POST /servicePrincipals                                      -> the enterprise application (service principal).
      6. POST /servicePrincipals/{graphSp}/appRoleAssignedTo          -> tenant-wide ADMIN CONSENT for the app role.
      7. (optional -IncludeDelegatedScope) also add the delegated scope, public-client redirect URI and an
         oauth2PermissionGrant (AllPrincipals) so the same app can be used with Connect-MgGraph -ClientId.
      8. Write HuntingDemo.settings.json (tenantId, clientId, endpoints - NEVER the secret) that
         Invoke-HuntingQuery.ps1 picks up automatically.

    Endpoints (login + Graph host) are resolved from the environment, not hard-coded: -Environment Public|AzureGov
    when given, otherwise the tenant's OpenID Connect discovery document (msgraph_host / token_endpoint).

    Who can run it: a user with Privileged Role Administrator (or Global Administrator). Cloud Application
    Administrator can create the app but CANNOT consent to Microsoft Graph application permissions.

.PARAMETER DisplayName
    Exact name of the app registration. By default, the signed-in user's alias and a random six-character
    alphanumeric suffix are appended to 'Graph Security API - Hunting Demo'. If an app with the resulting name
    already exists it is reused (a fresh secret is added; consent is verified).
.PARAMETER TenantId
    Tenant ID or verified domain to sign in to. Optional - also drives endpoint discovery.
.PARAMETER Environment
    Public (default when discovery is not possible) or AzureGov. Optional override; discovery is preferred.
.PARAMETER SecretValidityMonths
    Lifetime of the client secret in months (1-24). Default 12 = "good for one year".
.PARAMETER IncludeDelegatedScope
    Also configure the app for the delegated flow (scope + http://localhost public client + admin grant).
.PARAMETER PreviewName
    Sign in, generate the default app registration name, and exit before making any Graph or file changes.
.PARAMETER SettingsFile
    Where to write the settings JSON. Default: HuntingDemo.settings.json next to this script.

.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1
.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -SecretValidityMonths 12 -IncludeDelegatedScope
.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1 -Environment AzureGov -TenantId <gov-tenant-id>
.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1 -PreviewName

.LINK
    https://learn.microsoft.com/graph/api/application-post-applications
.LINK
    https://learn.microsoft.com/graph/api/application-addpassword
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
.LINK
    https://learn.microsoft.com/graph/api/oauth2permissiongrant-post
.LINK
    https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent
#>
[CmdletBinding()]
param(
    [string] $DisplayName,

    [string] $TenantId,

    [ValidateSet('Public', 'AzureGov')]
    [string] $Environment,

    [ValidateRange(1, 24)]
    [int] $SecretValidityMonths = 12,

    [switch] $IncludeDelegatedScope,

    [switch] $PreviewName,

    [string] $SettingsFile = (Join-Path $PSScriptRoot 'HuntingDemo.settings.json')
)

$ErrorActionPreference = 'Stop'
$DefaultDisplayName = 'Graph Security API - Hunting Demo'
$GraphAppId  = '00000003-0000-0000-c000-000000000000'     # Microsoft Graph's own (well-known) application ID
$Permission  = 'ThreatHunting.Read.All'

# ------------------------------------------------------------------------------------------------
# Endpoint resolution - the same function lives in Invoke-HuntingQuery.ps1.
# Order: explicit -Environment  ->  tenant OpenID discovery document (GET, anonymous)  ->  Public.
# ------------------------------------------------------------------------------------------------
function Resolve-DemoEndpoints {
    param([string] $TenantId, [string] $Environment)

    $envMap = [ordered]@{
        Public   = @{ LoginHost = 'https://login.microsoftonline.com'; GraphHost = 'https://graph.microsoft.com'; MgEnvironment = 'Global' }
        AzureGov = @{ LoginHost = 'https://login.microsoftonline.us';  GraphHost = 'https://graph.microsoft.us';  MgEnvironment = 'USGov'  }
    }
    $candidates = if ($Environment) { @($envMap[$Environment]) } else { @($envMap['Public'], $envMap['AzureGov']) }

    if ($TenantId) {
        foreach ($c in $candidates) {
            $discoveryUri = "$($c.LoginHost)/$TenantId/v2.0/.well-known/openid-configuration"
            try {
                $oidc = Invoke-RestMethod -Method Get -Uri $discoveryUri                 # REST call #0: GET, no token, JSON back
                $mgEnv = switch ($oidc.msgraph_host) {
                    'graph.microsoft.us'     { 'USGov' }
                    'dod-graph.microsoft.us' { 'USGovDoD' }
                    default                  { 'Global' }
                }
                return [pscustomobject]@{
                    Environment   = $(if ($mgEnv -eq 'Global') { 'Public' } else { 'AzureGov' })
                    MgEnvironment = $mgEnv
                    LoginHost     = $c.LoginHost
                    TokenEndpoint = $oidc.token_endpoint
                    GraphHost     = "https://$($oidc.msgraph_host)"
                    CloudInstance = $oidc.cloud_instance_name
                    Source        = "OpenID discovery: $discoveryUri"
                }
            }
            catch { Write-Verbose "Discovery at $($c.LoginHost) failed: $($_.Exception.Message)" }
        }
    }

    # No tenant (or discovery failed): take the URLs from the Graph PowerShell environment table when available.
    $c = $candidates[0]
    $mg = Get-MgEnvironment | Where-Object Name -eq $c.MgEnvironment
    $login = if ($mg) { $mg.AzureADEndpoint.TrimEnd('/') } else { $c.LoginHost }
    $graph = if ($mg) { $mg.GraphEndpoint.TrimEnd('/') }   else { $c.GraphHost }
    [pscustomobject]@{
        Environment   = $(if ($Environment) { $Environment } else { 'Public' })
        MgEnvironment = $c.MgEnvironment
        LoginHost     = $login
        TokenEndpoint = "$login/$(if ($TenantId) { $TenantId } else { 'organizations' })/oauth2/v2.0/token"
        GraphHost     = $graph
        CloudInstance = $null
        Source        = $(if ($mg) { "Get-MgEnvironment ($($c.MgEnvironment))" } else { 'built-in default' })
    }
}

function Invoke-Graph {
    # Thin wrapper so every call prints the verb + URI (the REST anatomy) before it runs.
    param([string] $Method, [string] $Uri, $Body)
    Write-Host ("  {0,-6} {1}" -f $Method.ToUpper(), $Uri) -ForegroundColor DarkGray
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}

function New-RandomAlphaNumericString {
    param([ValidateRange(1, 128)][int] $Length = 6)

    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $result = [char[]]::new($Length)
    for ($index = 0; $index -lt $Length; $index++) {
        $result[$index] = $characters[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($characters.Length)]
    }
    -join $result
}

# ------------------------------------------------------------------------------------------------
# 1. Sign in with the delegated scopes this script needs. An admin must consent to these too.
# ------------------------------------------------------------------------------------------------
$ep = Resolve-DemoEndpoints -TenantId $TenantId -Environment $Environment
Write-Host "`nEndpoints  : $($ep.Source)" -ForegroundColor Cyan
Write-Host "Login host : $($ep.LoginHost)   Graph host : $($ep.GraphHost)   Environment : $($ep.Environment) ($($ep.MgEnvironment))`n" -ForegroundColor DarkGray

$scopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
if ($IncludeDelegatedScope) { $scopes += 'DelegatedPermissionGrant.ReadWrite.All' }
$connect = @{ Scopes = $scopes; Environment = $ep.MgEnvironment; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect

$ctx = Get-MgContext
$tenant = $ctx.TenantId
$accountAlias = ($ctx.Account -split '@', 2)[0].Trim()
if ([string]::IsNullOrWhiteSpace($accountAlias)) { throw "Could not derive an alias from signed-in account '$($ctx.Account)'." }
if (-not $DisplayName) {
    $DisplayName = "$DefaultDisplayName - $accountAlias - $(New-RandomAlphaNumericString)"
}
# Pull the Graph host from the signed-in context's environment - the authoritative answer once logged in.
$mgEnvObj = Get-MgEnvironment | Where-Object Name -eq $(if ($ctx.Environment) { $ctx.Environment } else { $ep.MgEnvironment })
if ($mgEnvObj) { $ep.GraphHost = $mgEnvObj.GraphEndpoint.TrimEnd('/'); $ep.LoginHost = $mgEnvObj.AzureADEndpoint.TrimEnd('/') }
$g = "$($ep.GraphHost)/v1.0"
Write-Host "Signed in as $($ctx.Account) in tenant $tenant  |  scopes: $($ctx.Scopes -join ', ')`n" -ForegroundColor Green

if ($PreviewName) {
    Write-Host "Preview only - no Graph or file changes will be made." -ForegroundColor Yellow
    Write-Host "App registration name: $DisplayName" -ForegroundColor Cyan
    return [pscustomobject]@{
        Account     = $ctx.Account
        TenantId    = $tenant
        DisplayName = $DisplayName
    }
}

# ------------------------------------------------------------------------------------------------
# 2. Look up Microsoft Graph's service principal and the ThreatHunting.Read.All app role (no hard-coded GUIDs).
# ------------------------------------------------------------------------------------------------
Write-Host "Step 2  Resolve the '$Permission' permission on the Microsoft Graph service principal" -ForegroundColor Cyan
$graphSp = (Invoke-Graph -Method GET -Uri "$g/servicePrincipals?`$filter=appId%20eq%20'$GraphAppId'&`$select=id,appId,displayName,appRoles,oauth2PermissionScopes").value | Select-Object -First 1
if (-not $graphSp) { throw 'Microsoft Graph service principal not found in this tenant.' }

$appRole = $graphSp.appRoles | Where-Object { $_.value -eq $Permission -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
$scope   = $graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq $Permission } | Select-Object -First 1
if (-not $appRole) { throw "Application permission '$Permission' not found on Microsoft Graph." }
Write-Host ("        app role  {0}  = {1}  ({2})" -f $Permission, $appRole.id, $appRole.displayName) -ForegroundColor DarkGray
if ($IncludeDelegatedScope -and $scope) { Write-Host ("        scope     {0}  = {1}" -f $Permission, $scope.id) -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------------------------
# 3. The app registration - reuse by display name, or create it with requiredResourceAccess pre-filled.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 3  App registration '$DisplayName'" -ForegroundColor Cyan
$resourceAccess = @(@{ id = $appRole.id; type = 'Role' })                    # Role  = application permission
if ($IncludeDelegatedScope -and $scope) { $resourceAccess += @{ id = $scope.id; type = 'Scope' } }   # Scope = delegated

$escapedName = [uri]::EscapeDataString($DisplayName.Replace("'", "''"))          # OData: double the quotes, then URL-encode
$app = (Invoke-Graph -Method GET -Uri "$g/applications?`$filter=displayName%20eq%20'$escapedName'&`$select=id,appId,displayName,requiredResourceAccess").value | Select-Object -First 1
if ($app) {
    Write-Host "        reusing existing app  appId = $($app.appId)" -ForegroundColor Yellow
    $patch = @{ requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = $resourceAccess }) }
    if ($IncludeDelegatedScope) { $patch.isFallbackPublicClient = $true; $patch.publicClient = @{ redirectUris = @('http://localhost') } }
    Invoke-Graph -Method PATCH -Uri "$g/applications/$($app.id)" -Body $patch | Out-Null
}
else {
    $body = @{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'                              # single tenant
        description            = "Demo client for POST /security/runHuntingQuery ($Permission). Created $(Get-Date -Format u) by $($ctx.Account)."
        requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = $resourceAccess })
    }
    if ($IncludeDelegatedScope) { $body.isFallbackPublicClient = $true; $body.publicClient = @{ redirectUris = @('http://localhost') } }
    $app = Invoke-Graph -Method POST -Uri "$g/applications" -Body $body
    Write-Host "        created  appId (client ID) = $($app.appId)   objectId = $($app.id)" -ForegroundColor Green
}

# ------------------------------------------------------------------------------------------------
# 4. Client secret, valid for $SecretValidityMonths months. secretText is returned ONCE - never again.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 4  Client secret ($SecretValidityMonths months)" -ForegroundColor Cyan
$endDate  = (Get-Date).ToUniversalTime().AddMonths($SecretValidityMonths)
$secretResult = Invoke-Graph -Method POST -Uri "$g/applications/$($app.id)/addPassword" -Body @{
    passwordCredential = @{
        displayName = "Hunting demo secret ($(Get-Date -Format 'yyyy-MM-dd'))"
        endDateTime = $endDate.ToString('yyyy-MM-ddTHH:mm:ssZ')             # ISO 8601, UTC
    }
}
$secretPlain  = $secretResult.secretText
$secretSecure = ConvertTo-SecureString -String $secretPlain -AsPlainText -Force
Write-Host ("        keyId = {0}   expires = {1:u}" -f $secretResult.keyId, [datetime]$secretResult.endDateTime) -ForegroundColor Green

# ------------------------------------------------------------------------------------------------
# 5. Service principal (the "Enterprise application") - consent is recorded on this object, not on the app.
# ------------------------------------------------------------------------------------------------
Write-Host 'Step 5  Service principal' -ForegroundColor Cyan
$sp = $null
try   { $sp = Invoke-Graph -Method GET -Uri "$g/servicePrincipals(appId='$($app.appId)')?`$select=id,appId,displayName" }
catch { $sp = $null }
if (-not $sp) {
    $sp = Invoke-Graph -Method POST -Uri "$g/servicePrincipals" -Body @{ appId = $app.appId }
    Write-Host "        created  servicePrincipal id = $($sp.id)" -ForegroundColor Green
}
else { Write-Host "        exists   servicePrincipal id = $($sp.id)" -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------------------------
# 6. ADMIN CONSENT for the application permission = an appRoleAssignment on Microsoft Graph's service principal:
#    principalId = our SP, resourceId = Graph SP, appRoleId = ThreatHunting.Read.All. Same effect as the
#    "Grant admin consent" button. Retries cover directory replication right after creation.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 6  Admin consent (appRoleAssignment) for $Permission" -ForegroundColor Cyan
$existing = (Invoke-Graph -Method GET -Uri "$g/servicePrincipals/$($sp.id)/appRoleAssignments").value |
    Where-Object { $_.appRoleId -eq $appRole.id -and $_.resourceId -eq $graphSp.id }
if ($existing) {
    Write-Host '        already granted' -ForegroundColor DarkGray
}
else {
    $granted = $false
    for ($attempt = 1; $attempt -le 6 -and -not $granted; $attempt++) {
        try {
            $assignment = Invoke-Graph -Method POST -Uri "$g/servicePrincipals/$($graphSp.id)/appRoleAssignedTo" -Body @{
                principalId = $sp.id
                resourceId  = $graphSp.id
                appRoleId   = $appRole.id
            }
            $granted = $true
            Write-Host "        granted  assignment id = $($assignment.id)  ($($assignment.principalDisplayName) -> $($assignment.resourceDisplayName))" -ForegroundColor Green
        }
        catch {
            if ($attempt -eq 6) { throw }
            Write-Host "        not ready yet (replication) - retry $attempt/5 in 5 s ..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
        }
    }
}

# ------------------------------------------------------------------------------------------------
# 7. Optional: delegated grant (AllPrincipals) so Connect-MgGraph -ClientId <appId> -Scopes ThreatHunting.Read.All
#    signs in without a consent prompt. Skip this to let the class SEE the prompt with the SDK's default app.
# ------------------------------------------------------------------------------------------------
if ($IncludeDelegatedScope -and $scope) {
    Write-Host "Step 7  Delegated admin consent (oauth2PermissionGrant) for $Permission" -ForegroundColor Cyan
    $grant = (Invoke-Graph -Method GET -Uri "$g/oauth2PermissionGrants?`$filter=clientId%20eq%20'$($sp.id)'%20and%20resourceId%20eq%20'$($graphSp.id)'").value |
        Where-Object { $_.consentType -eq 'AllPrincipals' } | Select-Object -First 1
    if ($grant -and ($grant.scope -split ' ') -contains $Permission) {
        Write-Host '        already granted' -ForegroundColor DarkGray
    }
    elseif ($grant) {
        Invoke-Graph -Method PATCH -Uri "$g/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = ("$($grant.scope) $Permission").Trim() } | Out-Null
        Write-Host '        scope added to existing grant' -ForegroundColor Green
    }
    else {
        Invoke-Graph -Method POST -Uri "$g/oauth2PermissionGrants" -Body @{
            clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = $Permission
        } | Out-Null
        Write-Host '        granted' -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------------------------
# 8. Settings for Invoke-HuntingQuery.ps1 - identifiers and endpoints only. The secret is NOT written to disk.
# ------------------------------------------------------------------------------------------------
$settings = [ordered]@{
    displayName        = $app.displayName
    tenantId           = $tenant
    clientId           = $app.appId
    appObjectId        = $app.id
    servicePrincipalId = $sp.id
    environment        = $ep.Environment
    mgEnvironment      = $(if ($mgEnvObj) { $mgEnvObj.Name } else { $ep.MgEnvironment })
    loginHost          = $ep.LoginHost
    graphHost          = $ep.GraphHost
    permission         = $Permission
    delegatedScope     = [bool]$IncludeDelegatedScope
    secretKeyId        = $secretResult.keyId
    secretExpiresUtc   = $endDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    createdUtc         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$settings | ConvertTo-Json -Depth 3 | Set-Content -Path $SettingsFile -Encoding utf8
Write-Host "`nSettings written (no secret) -> $SettingsFile" -ForegroundColor Green

Write-Host "`n================  COPY THE SECRET NOW - IT CANNOT BE RETRIEVED LATER  ================" -ForegroundColor Yellow
Write-Host "  Tenant ID : $tenant"
Write-Host "  Client ID : $($app.appId)"
Write-Host "  Secret    : $secretPlain" -ForegroundColor Yellow
Write-Host "  Expires   : $($endDate.ToString('u'))"
Write-Host "=======================================================================================`n" -ForegroundColor Yellow
Write-Host "Store it outside the script, e.g.  `$env:HUNT_CLIENT_SECRET = '<secret>'   or a SecretManagement vault." -ForegroundColor DarkGray
Write-Host "Portal check: Entra admin center > App registrations > '$DisplayName' > API permissions  (status: Granted for <tenant>)." -ForegroundColor DarkGray
Write-Host "Alternative consent URL: $($ep.LoginHost)/$tenant/adminconsent?client_id=$($app.appId)" -ForegroundColor DarkGray
Write-Host "`nAllow 1-2 minutes for replication, then run:  .\scripts\Invoke-HuntingQuery.ps1 -AuthMode AppOnly`n" -ForegroundColor Cyan

# Return an object for pipeline use (secret as SecureString)
[pscustomobject]@{
    TenantId        = $tenant
    ClientId        = $app.appId
    ClientSecret    = $secretSecure
    SecretExpiresOn = $endDate
    Environment     = $ep.Environment
    GraphHost       = $ep.GraphHost
    SettingsFile    = $SettingsFile
}
