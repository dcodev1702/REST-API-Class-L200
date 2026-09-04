#Requires -Version 7.3
#Requires -Modules Microsoft.Graph.Authentication
# Author: DCODEV1702 & GHCP (ChatGPT 5.6 Sol)
# Date: 2026-09-03
<#
.SYNOPSIS
    Creates (or reuses) the Entra ID app registration used by the authentication demos - programmatically, through
    Microsoft Graph REST calls - including the ThreatHunting.Read.All application permission, tenant-wide
    admin consent, a client secret, and a self-signed certificate marked for training only.

.DESCRIPTION
    Companion to Invoke-HuntingQuery.ps1 for the session "REST APIs, JSON & the Microsoft Graph Security API".
    Every step is a Microsoft Graph REST call issued with Invoke-MgGraphRequest, so the class sees that the
    Entra admin center is just another REST client:

      1. Sign in (Connect-MgGraph), verify every requested delegated scope, and use read-only Graph calls to
         confirm that Privileged Role Administrator or Global Administrator is active (including through PIM).
      2. GET  /servicePrincipals?$filter=appId eq '<Microsoft Graph>'  -> look up the ThreatHunting.Read.All
         app role id (application permission) instead of hard-coding a GUID. No resource writes occur before
         both permission checks pass.
      3. POST /applications                                           -> the app registration (single tenant)
         with requiredResourceAccess = Microsoft Graph / ThreatHunting.Read.All (Role).
            4. Create an RSA-4096/SHA-256 self-signed certificate in Cert:\CurrentUser\My (12 months by default) and
         PATCH /applications/{id}                                    -> upload its public key as a credential.
      5. POST /applications/{id}/addPassword                          -> client secret, endDateTime = now + 12 months.
      6. POST /servicePrincipals                                      -> the enterprise application (service principal).
      7. POST /servicePrincipals/{graphSp}/appRoleAssignedTo          -> tenant-wide ADMIN CONSENT for the app role.
      8. (optional -IncludeDelegatedScope) also add the delegated scope, loopback + WAM broker redirect URIs and an
         oauth2PermissionGrant (AllPrincipals) so the same app can use delegated WAM sign-in without a cert or secret.
      9. Write HuntingDemo.settings.json (tenantId, clientId, certificate metadata, endpoints - NEVER the secret
         or private key) that Invoke-HuntingQuery.ps1 picks up automatically.

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
    Lifetime of the client secret in months (1-1000). Default 12 = "good for one year".
.PARAMETER CertificateValidityMonths
    Lifetime of the training-only self-signed certificate in months (1-1000). Default 12. The private key is
    non-exportable and remains in Cert:\CurrentUser\My.
.PARAMETER IncludeDelegatedScope
    Also configure delegated WAM authentication (scope + loopback/broker redirect URIs + admin grant).
.PARAMETER PreviewName
    Sign in, generate the default app registration name, and exit before making any Graph or file changes.
.PARAMETER SettingsFile
    Where to write the settings JSON. Default: HuntingDemo.settings.json next to this script.

.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1
.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -CertificateValidityMonths 12 -IncludeDelegatedScope
.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1 -Environment AzureGov -TenantId <gov-tenant-id>
.EXAMPLE
    .\scripts\New-HuntingAppRegistration.ps1 -PreviewName

.LINK
    https://learn.microsoft.com/graph/api/application-post-applications
.LINK
    https://learn.microsoft.com/graph/api/application-addpassword
.LINK
    https://learn.microsoft.com/graph/applications-how-to-add-certificate
.LINK
    https://learn.microsoft.com/entra/identity-platform/howto-create-self-signed-certificate
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
.LINK
    https://learn.microsoft.com/graph/api/oauth2permissiongrant-post
.LINK
    https://learn.microsoft.com/graph/api/user-list-transitivememberof
.LINK
    https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent
#>
[CmdletBinding()]
param(
    [string] $DisplayName,

    [string] $TenantId,

    [ValidateSet('Public', 'AzureGov')]
    [string] $Environment,

    [ValidateRange(1, 1000)]
    [int] $SecretValidityMonths = 12,

    [ValidateRange(1, 1000)]
    [int] $CertificateValidityMonths = 12,

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
    param([string] $Method, [string] $Uri, $Body, [hashtable] $Headers)
    Write-Host ("  {0,-6} {1}" -f $Method.ToUpper(), $Uri) -ForegroundColor DarkGray
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    if ($Headers) { $p.Headers = $Headers }
    Invoke-MgGraphRequest @p
}

function Assert-SetupPermissions {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string[]] $RequiredScopes,

        [Parameter(Mandatory)]
        [string] $GraphBaseUri
    )

    $grantedScopes = @($Context.Scopes)
    $missingScopes = @($RequiredScopes | Where-Object { $grantedScopes -notcontains $_ })
    if ($missingScopes.Count -gt 0) {
        throw "Permission preflight failed before resource creation. The Graph token is missing delegated scope(s): $($missingScopes -join ', '). Disconnect-MgGraph and run the setup again to grant the requested scopes."
    }

    $acceptedRoleNames = @('Privileged Role Administrator', 'Global Administrator')
    $roleTemplates = @(
        (Invoke-Graph -Method GET -Uri "$GraphBaseUri/directoryRoleTemplates?`$select=id,displayName").value |
            Where-Object { $_.displayName -in $acceptedRoleNames }
    )
    $missingRoleTemplates = @($acceptedRoleNames | Where-Object { $_ -notin @($roleTemplates.displayName) })
    if ($missingRoleTemplates.Count -gt 0) {
        throw "Permission preflight could not resolve required Entra role template(s): $($missingRoleTemplates -join ', '). No resources have been created."
    }

    $membershipHeaders = @{ ConsistencyLevel = 'eventual' }
    $activeRoles = @(
        (Invoke-Graph -Method GET `
            -Uri "$GraphBaseUri/me/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName,roleTemplateId&`$count=true" `
            -Headers $membershipHeaders).value
    )
    $acceptedRoleTemplateIds = @($roleTemplates.id)
    $authorizedRole = $activeRoles |
        Where-Object { $_.roleTemplateId -in $acceptedRoleTemplateIds } |
        Select-Object -First 1
    if (-not $authorizedRole) {
        $activeRoleNames = @($activeRoles.displayName | Where-Object { $_ } | Sort-Object -Unique)
        $activeRoleSummary = if ($activeRoleNames.Count -gt 0) { $activeRoleNames -join ', ' } else { 'none' }
        throw "Permission preflight failed before resource creation. '$($Context.Account)' must have an active Privileged Role Administrator or Global Administrator role. Active roles: $activeRoleSummary. Activate PIM and run the setup again."
    }

    Write-Host "        delegated scopes verified: $($RequiredScopes -join ', ')" -ForegroundColor Green
    Write-Host "        active Entra role verified: $($authorizedRole.displayName)" -ForegroundColor Green
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

function New-TrainingCertificate {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName] $DistinguishedName,

        [Parameter(Mandatory)]
        [string] $FriendlyName,

        [Parameter(Mandatory)]
        [datetime] $NotBefore,

        [Parameter(Mandatory)]
        [datetime] $NotAfter
    )

    $rsa = $null
    $createdCertificate = $null
    $persistedCertificate = $null
    $certificateStore = $null
    $pfxBytes = $null
    $pfxPassword = $null
    $storedThumbprint = $null

    try {
        # LOCAL KEYPAIR CREATION: RSA generates a 4096-bit public/private keypair in this PowerShell process.
        # The private key remains local and is never included in a Microsoft Graph request.
        $rsa = [System.Security.Cryptography.RSA]::Create(4096)
        $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $DistinguishedName,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        [void] $certificateRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
        )
        [void] $certificateRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
                $true
            )
        )
        $enhancedKeyUsages = [System.Security.Cryptography.OidCollection]::new()
        [void] $enhancedKeyUsages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2', 'Client Authentication'))
        [void] $certificateRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($enhancedKeyUsages, $false)
        )

        # LOCAL CERTIFICATE CREATION: self-sign the X.509 certificate in memory; no Graph call occurs here.
        $createdCertificate = $certificateRequest.CreateSelfSigned(
            [DateTimeOffset] $NotBefore.ToUniversalTime(),
            [DateTimeOffset] $NotAfter.ToUniversalTime()
        )

        # Reimport without the Exportable flag so the installed CurrentUser private key cannot be exported.
        $pfxPassword = [guid]::NewGuid().ToString('N')
        $pfxBytes = $createdCertificate.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12,
            $pfxPassword
        )
        $storageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
        $persistedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxBytes,
            $pfxPassword,
            $storageFlags
        )
        $persistedCertificate.FriendlyName = $FriendlyName
        $storedThumbprint = $persistedCertificate.Thumbprint

        # LOCAL CERTIFICATE STORAGE: copy the certificate and non-exportable private key to CurrentUser > Personal.
        $certificateStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        $certificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $certificateStore.Add([System.Security.Cryptography.X509Certificates.X509Certificate2] $persistedCertificate)
        $certificateStore.Close()

        $storedCertificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$storedThumbprint" -ErrorAction Stop
        if (-not $storedCertificate.HasPrivateKey) { throw 'The certificate was copied to the store without its private key.' }
        $storedCertificate
    }
    catch {
        if ($storedThumbprint) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$storedThumbprint" -DeleteKey -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    finally {
        if ($certificateStore) { $certificateStore.Close(); $certificateStore.Dispose() }
        if ($persistedCertificate) { $persistedCertificate.Dispose() }
        if ($createdCertificate) { $createdCertificate.Dispose() }
        if ($rsa) { $rsa.Dispose() }
        if ($pfxBytes) { [Array]::Clear($pfxBytes, 0, $pfxBytes.Length) }
        $pfxPassword = $null
    }
}

# ------------------------------------------------------------------------------------------------
# 1. Sign in with the delegated scopes this script needs. An admin must consent to these too.
# ------------------------------------------------------------------------------------------------
$ep = Resolve-DemoEndpoints -TenantId $TenantId -Environment $Environment
Write-Host "`nEndpoints  : $($ep.Source)" -ForegroundColor Cyan
Write-Host "Login host : $($ep.LoginHost)   Graph host : $($ep.GraphHost)   Environment : $($ep.Environment) ($($ep.MgEnvironment))`n" -ForegroundColor DarkGray

$scopes = @('User.Read', 'RoleManagement.Read.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
if ($IncludeDelegatedScope) { $scopes += 'DelegatedPermissionGrant.ReadWrite.All' }
$connect = @{ Scopes = $scopes; Environment = $ep.MgEnvironment; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Set-MgGraphOption -DisableLoginByWAM $false
Connect-MgGraph @connect

$ctx = Get-MgContext
$tenant = $ctx.TenantId
$accountAlias = ($ctx.Account -split '@', 2)[0].Trim()
if ([string]::IsNullOrWhiteSpace($accountAlias)) { throw "Could not derive an alias from signed-in account '$($ctx.Account)'." }
if (-not $DisplayName) {
    $DisplayName = "$DefaultDisplayName - $accountAlias - $(New-RandomAlphaNumericString)"
}
$certificatePurpose = 'TRAINING ONLY - SELF-SIGNED - NOT FOR PRODUCTION'
$certificateName = "$DisplayName - TRAINING"
$distinguishedNameBuilder = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameBuilder]::new()
[void] $distinguishedNameBuilder.AddCommonName($certificateName)
$certificateDistinguishedName = $distinguishedNameBuilder.Build()
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
        CertificateName = $certificateName
    }
}

# ------------------------------------------------------------------------------------------------
# 2. Validate every required permission and active admin role before the first resource write, then look up
#    Microsoft Graph's service principal and the ThreatHunting.Read.All app role (no hard-coded GUIDs).
# ------------------------------------------------------------------------------------------------
Write-Host 'Step 2  Permission and active-role preflight (read-only)' -ForegroundColor Cyan
Assert-SetupPermissions -Context $ctx -RequiredScopes $scopes -GraphBaseUri $g

Write-Host "        resolve '$Permission' on the Microsoft Graph service principal" -ForegroundColor Cyan
# PERMISSION LOOKUP: read Microsoft Graph's published permission IDs. This does not grant consent yet.
$graphSp = (Invoke-Graph -Method GET -Uri "$g/servicePrincipals?`$filter=appId%20eq%20'$GraphAppId'&`$select=id,appId,displayName,appRoles,oauth2PermissionScopes").value | Select-Object -First 1
if (-not $graphSp) { throw 'Microsoft Graph service principal not found in this tenant.' }

$appRole = $graphSp.appRoles | Where-Object { $_.value -eq $Permission -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
$scope   = $graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq $Permission } | Select-Object -First 1
if (-not $appRole) { throw "Application permission '$Permission' not found on Microsoft Graph." }
if ($IncludeDelegatedScope -and -not $scope) { throw "Delegated permission '$Permission' was requested but was not found on Microsoft Graph." }
Write-Host ("        app role  {0}  = {1}  ({2})" -f $Permission, $appRole.id, $appRole.displayName) -ForegroundColor DarkGray
if ($IncludeDelegatedScope) { Write-Host ("        scope     {0}  = {1}" -f $Permission, $scope.id) -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------------------------
# 3. The app registration - reuse by display name, or create it with requiredResourceAccess pre-filled.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 3  App registration '$DisplayName'" -ForegroundColor Cyan
# PERMISSION DECLARATION: requiredResourceAccess records what the app requests; it is not admin consent.
$resourceAccess = @(@{ id = $appRole.id; type = 'Role' })                    # Role  = application permission
if ($IncludeDelegatedScope) { $resourceAccess += @{ id = $scope.id; type = 'Scope' } }   # Scope = delegated

$escapedName = [uri]::EscapeDataString($DisplayName.Replace("'", "''"))          # OData: double the quotes, then URL-encode
$app = (Invoke-Graph -Method GET -Uri "$g/applications?`$filter=displayName%20eq%20'$escapedName'&`$select=id,appId,displayName,requiredResourceAccess,keyCredentials").value | Select-Object -First 1
if ($app) {
    Write-Host "        reusing existing app  appId = $($app.appId)" -ForegroundColor Yellow
    $patch = @{ requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = $resourceAccess }) }
    if ($IncludeDelegatedScope) {
        $patch.isFallbackPublicClient = $true
        $patch.publicClient = @{ redirectUris = @('http://localhost', "ms-appx-web://microsoft.aad.brokerplugin/$($app.appId)") }
    }
    # APP REGISTRATION UPDATE: PATCH the existing application object with its requested permissions/settings.
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
    # APP REGISTRATION CREATION: POST /applications creates the Entra application object.
    $app = Invoke-Graph -Method POST -Uri "$g/applications" -Body $body
    Write-Host "        created  appId (client ID) = $($app.appId)   objectId = $($app.id)" -ForegroundColor Green
    if ($IncludeDelegatedScope) {
        Invoke-Graph -Method PATCH -Uri "$g/applications/$($app.id)" -Body @{
            publicClient = @{ redirectUris = @('http://localhost', "ms-appx-web://microsoft.aad.brokerplugin/$($app.appId)") }
        } | Out-Null
    }
}

# ------------------------------------------------------------------------------------------------
# 4. Training-only certificate. Rotate this app's training key while preserving unrelated certificates.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 4  TRAINING ONLY self-signed certificate ($CertificateValidityMonths months)" -ForegroundColor Cyan
$certificateFriendlyName = $certificateName
$certificateStart = (Get-Date).ToUniversalTime().AddMinutes(-5)
$certificateEnd = $certificateStart.AddMonths($CertificateValidityMonths)
# LOCAL CERTIFICATE CREATION: create and store the self-signed certificate before registering it with Entra.
$certificate = New-TrainingCertificate `
    -DistinguishedName $certificateDistinguishedName `
    -FriendlyName $certificateFriendlyName `
    -NotBefore $certificateStart `
    -NotAfter $certificateEnd

$certificateRegistered = $false
try {
    $certificateKeyId = [guid]::NewGuid()
    $certificateCredentialName = if ($certificateName.Length -le 90) { $certificateName } else { $certificateName.Substring(0, 90) }
    # PUBLIC CERTIFICATE PAYLOAD: RawData is the DER-encoded X.509 public certificate.
    # It contains the public key and certificate metadata, never the private key.
    $certificateCredential = @{
        customKeyIdentifier = [Convert]::ToBase64String($certificate.GetCertHash())
        displayName         = $certificateCredentialName
        endDateTime         = $certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        key                 = [Convert]::ToBase64String($certificate.RawData)
        keyId               = $certificateKeyId
        startDateTime       = $certificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        type                = 'AsymmetricX509Cert'
        usage               = 'Verify'
    }

    $preservedKeyCredentials = @(
        foreach ($existingCredential in @($app.keyCredentials)) {
            if ($existingCredential.displayName -eq $certificateCredentialName) { continue }
            if (-not $existingCredential.key) {
                throw "Cannot preserve existing certificate '$($existingCredential.displayName)' because Microsoft Graph did not return its public key."
            }

            $existingKey = if ($existingCredential.key -is [byte[]]) {
                [Convert]::ToBase64String($existingCredential.key)
            }
            else { [string] $existingCredential.key }
            $existingCustomKeyIdentifier = if ($existingCredential.customKeyIdentifier -is [byte[]]) {
                [Convert]::ToBase64String($existingCredential.customKeyIdentifier)
            }
            else { [string] $existingCredential.customKeyIdentifier }

            @{
                customKeyIdentifier = $existingCustomKeyIdentifier
                displayName         = $existingCredential.displayName
                endDateTime         = ([datetime] $existingCredential.endDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                key                 = $existingKey
                keyId               = [string] $existingCredential.keyId
                startDateTime       = ([datetime] $existingCredential.startDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                type                = $existingCredential.type
                usage               = $existingCredential.usage
            }
        }
    )
    $updatedKeyCredentials = @($preservedKeyCredentials) + @($certificateCredential)

    # PUBLIC CERTIFICATE UPLOAD: PATCH the app registration's keyCredentials with public material only.
    Invoke-Graph -Method PATCH -Uri "$g/applications/$($app.id)" -Body @{ keyCredentials = $updatedKeyCredentials } | Out-Null
    $certificateRegistered = $true
}
finally {
    if (-not $certificateRegistered) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -DeleteKey -Force -ErrorAction SilentlyContinue
    }
}

$staleTrainingCertificates = @(Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object {
    $_.FriendlyName -eq $certificateName -and $_.Thumbprint -ne $certificate.Thumbprint
})
foreach ($staleCertificate in $staleTrainingCertificates) {
    Remove-Item -LiteralPath $staleCertificate.PSPath -DeleteKey -Force
    Write-Host "        removed stale local training certificate $($staleCertificate.Thumbprint)" -ForegroundColor DarkGray
}

$certificateSha256 = $certificate.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)
Write-Host '        ============== TRAINING ONLY CERTIFICATE DETAILS =============' -ForegroundColor Yellow
Write-Host "        Purpose       : $certificatePurpose" -ForegroundColor Yellow
Write-Host "        Cert name     : $certificateName"
Write-Host "        App name      : $DisplayName"
Write-Host "        Client ID     : $($app.appId)"
Write-Host "        App object ID : $($app.id)"
Write-Host "        Tenant ID     : $tenant"
Write-Host "        Subject       : $($certificate.Subject)"
Write-Host "        Friendly name : $($certificate.FriendlyName)"
Write-Host "        App key name  : $certificateCredentialName"
Write-Host "        Store         : Cert:\CurrentUser\My"
Write-Host "        Thumbprint    : $($certificate.Thumbprint)"
Write-Host "        SHA-256       : $certificateSha256"
Write-Host "        Key ID        : $certificateKeyId"
Write-Host "        Private key   : Non-exportable; local CurrentUser store only"
Write-Host ("        Valid UTC     : {0:u} through {1:u}" -f $certificate.NotBefore.ToUniversalTime(), $certificate.NotAfter.ToUniversalTime())
Write-Host '        =============================================================' -ForegroundColor Yellow

# ------------------------------------------------------------------------------------------------
# 5. Client secret, valid for $SecretValidityMonths months. secretText is returned ONCE - never again.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 5  Client secret ($SecretValidityMonths months)" -ForegroundColor Cyan
$endDate  = (Get-Date).ToUniversalTime().AddMonths($SecretValidityMonths)
# CLIENT SECRET CREATION: Microsoft Graph generates the secret on the app registration.
# addPassword returns secretText exactly once; only its key ID and expiry go into settings.
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
# 6. Service principal (the "Enterprise application") - consent is recorded on this object, not on the app.
# ------------------------------------------------------------------------------------------------
Write-Host 'Step 6  Service principal' -ForegroundColor Cyan
$sp = $null
try   { $sp = Invoke-Graph -Method GET -Uri "$g/servicePrincipals(appId='$($app.appId)')?`$select=id,appId,displayName" }
catch { $sp = $null }
if (-not $sp) {
    # SERVICE PRINCIPAL CREATION: instantiate the app in this tenant as its Enterprise application.
    $sp = Invoke-Graph -Method POST -Uri "$g/servicePrincipals" -Body @{ appId = $app.appId }
    Write-Host "        created  servicePrincipal id = $($sp.id)" -ForegroundColor Green
}
else { Write-Host "        exists   servicePrincipal id = $($sp.id)" -ForegroundColor DarkGray }

# ------------------------------------------------------------------------------------------------
# 7. ADMIN CONSENT for the application permission = an appRoleAssignment on Microsoft Graph's service principal:
#    principalId = our SP, resourceId = Graph SP, appRoleId = ThreatHunting.Read.All. Same effect as the
#    "Grant admin consent" button. Retries cover directory replication right after creation.
# ------------------------------------------------------------------------------------------------
Write-Host "Step 7  Admin consent (appRoleAssignment) for $Permission" -ForegroundColor Cyan
$existing = (Invoke-Graph -Method GET -Uri "$g/servicePrincipals/$($sp.id)/appRoleAssignments").value |
    Where-Object { $_.appRoleId -eq $appRole.id -and $_.resourceId -eq $graphSp.id }
if ($existing) {
    Write-Host '        already granted' -ForegroundColor DarkGray
}
else {
    $granted = $false
    for ($attempt = 1; $attempt -le 6 -and -not $granted; $attempt++) {
        try {
            # APPLICATION ROLE ASSIGNMENT: this POST is the actual tenant-wide admin consent operation.
            # principalId = our Enterprise app; resourceId = Microsoft Graph; appRoleId = ThreatHunting.Read.All.
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
# 8. Optional: delegated grant (AllPrincipals) for the custom public client used by WAM.
#    WAM authenticates the user; no client secret or certificate participates in this flow.
# ------------------------------------------------------------------------------------------------
if ($IncludeDelegatedScope -and $scope) {
    Write-Host "Step 8  Delegated admin consent (oauth2PermissionGrant) for $Permission" -ForegroundColor Cyan
    $grant = (Invoke-Graph -Method GET -Uri "$g/oauth2PermissionGrants?`$filter=clientId%20eq%20'$($sp.id)'%20and%20resourceId%20eq%20'$($graphSp.id)'").value |
        Where-Object { $_.consentType -eq 'AllPrincipals' } | Select-Object -First 1
    if ($grant -and ($grant.scope -split ' ') -contains $Permission) {
        Write-Host '        already granted' -ForegroundColor DarkGray
    }
    elseif ($grant) {
        # DELEGATED CONSENT UPDATE: add the scope to an existing tenant-wide OAuth permission grant.
        Invoke-Graph -Method PATCH -Uri "$g/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = ("$($grant.scope) $Permission").Trim() } | Out-Null
        Write-Host '        scope added to existing grant' -ForegroundColor Green
    }
    else {
        # DELEGATED CONSENT CREATION: AllPrincipals grants this delegated scope tenant-wide.
        Invoke-Graph -Method POST -Uri "$g/oauth2PermissionGrants" -Body @{
            clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = $Permission
        } | Out-Null
        Write-Host '        granted' -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------------------------
# 9. Settings for Invoke-HuntingQuery.ps1. Neither the secret nor certificate private key is written to disk.
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
    certificatePurpose = $certificatePurpose
    certificateName    = $certificateName
    certificateStore   = 'Cert:\CurrentUser\My'
    certificateSubject = $certificate.Subject
    certificateFriendlyName = $certificate.FriendlyName
    certificateThumbprint = $certificate.Thumbprint
    certificateSha256  = $certificateSha256
    certificateKeyId   = $certificateKeyId.ToString()
    certificateNotBeforeUtc = $certificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    certificateExpiresUtc = $certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    secretKeyId        = $secretResult.keyId
    secretExpiresUtc   = $endDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    createdUtc         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
# LOCAL SETTINGS WRITE: persist identifiers and metadata only; neither credential value is written here.
$settings | ConvertTo-Json -Depth 3 | Set-Content -Path $SettingsFile -Encoding utf8
Write-Host "`nSettings written (no secret) -> $SettingsFile" -ForegroundColor Green

Write-Host "`n================  COPY THE SECRET NOW - IT CANNOT BE RETRIEVED LATER  ================" -ForegroundColor Yellow
Write-Host "  Tenant ID : $tenant"
Write-Host "  Client ID : $($app.appId)"
Write-Host "  Secret    : $secretPlain" -ForegroundColor Yellow
Write-Host "  Expires   : $($endDate.ToString('u'))"
Write-Host "=======================================================================================`n" -ForegroundColor Yellow
Write-Host "Store it outside the script, e.g.  `$env:HUNT_CLIENT_SECRET = '<secret>'   or a SecretManagement vault." -ForegroundColor DarkGray
Write-Host "Certificate auth: .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Certificate" -ForegroundColor Cyan
Write-Host "Portal check: Entra admin center > App registrations > '$DisplayName' > API permissions  (status: Granted for <tenant>)." -ForegroundColor DarkGray
Write-Host "Alternative consent URL: $($ep.LoginHost)/$tenant/adminconsent?client_id=$($app.appId)" -ForegroundColor DarkGray
Write-Host "`nAllow 1-2 minutes for replication, then run:  .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Secret`n" -ForegroundColor Cyan

# Return an object for pipeline use (secret as SecureString)
[pscustomobject]@{
    TenantId        = $tenant
    ClientId        = $app.appId
    ClientSecret    = $secretSecure
    SecretExpiresOn = $endDate
    CertificatePurpose = $certificatePurpose
    CertificateThumbprint = $certificate.Thumbprint
    CertificateExpiresOn = $certificate.NotAfter
    Environment     = $ep.Environment
    GraphHost       = $ep.GraphHost
    SettingsFile    = $SettingsFile
}
