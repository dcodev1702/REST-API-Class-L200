#Requires -Version 7.0
<#
.SYNOPSIS
    Runs a Microsoft Defender XDR advanced hunting query through the Microsoft Graph Security API
    (POST /security/runHuntingQuery) and writes the JSON response to a file.

.DESCRIPTION
    Companion script for the session "REST APIs, JSON & the Microsoft Graph Security API".
    Every REST concept is called out in the comments: verb, URI, headers, body, status code,
    response headers, response body (JSON) -> PowerShell objects -> JSON file.

    Two ways to authenticate - run both so learners experience the difference:

      AppOnly    OAuth 2.0 client-credentials flow, done by hand with Invoke-RestMethod so you can see the
                 token request as a REST call. Uses the app registration created by New-HuntingAppRegistration.ps1
                 (Application permission ThreatHunting.Read.All + tenant-wide admin consent + 12-month secret).
                 No user is involved; the token carries a "roles" claim.

      Delegated  Interactive sign-in through the Microsoft Graph PowerShell SDK (Connect-MgGraph) requesting
                 the delegated scope ThreatHunting.Read.All. The first run in a tenant shows the consent prompt
                 (admin consent required); the token carries an "scp" claim. Needs Microsoft.Graph.Authentication.

    Endpoints are NOT hard-coded. Resolution order:
      1. -Environment Public | AzureGov, when given (URLs pulled from Get-MgEnvironment when the SDK is present).
      2. Otherwise the tenant's OpenID Connect discovery document -
         GET https://login.microsoftonline.{com|us}/{tenant}/v2.0/.well-known/openid-configuration -
         which returns token_endpoint and msgraph_host (graph.microsoft.com, graph.microsoft.us, dod-graph.microsoft.us).
      3. In Delegated mode the Graph host is re-read from the signed-in context (Get-MgContext / Get-MgEnvironment).

    TenantId / ClientId / Environment default to the values in HuntingDemo.settings.json (written by
    New-HuntingAppRegistration.ps1) when the file exists next to this script.

    Default query: every user who signed in successfully during the last N hours (default 24), one row per
    account, from the EntraIdSignInEvents table (requires Microsoft Entra ID P2).

.PARAMETER AuthMode
    AppOnly (default) or Delegated.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain. Required for AppOnly unless present in the settings file.
.PARAMETER ClientId
    Application (client) ID. Required for AppOnly unless present in the settings file.
.PARAMETER ClientSecret
    Client secret as a SecureString. If omitted, $env:HUNT_CLIENT_SECRET is used, otherwise you are prompted.
.PARAMETER Environment
    Public or AzureGov. Optional override - when omitted the cloud is discovered from the tenant.
.PARAMETER Hours
    Look-back window in hours (1-720). Default 24.
.PARAMETER QueryFile
    Optional .kql file sent verbatim as the Query (Hours then only drives the API Timespan).
.PARAMETER OutFile
    Output path. Default: .\SignIns-Last<Hours>h-<yyyyMMdd-HHmm>.json
.PARAMETER TokenOutFile
    Optional path for the raw JWT access token. Treat this file as a bearer credential and delete it after the demo.
.PARAMETER SettingsFile
    Settings JSON written by New-HuntingAppRegistration.ps1. Default: HuntingDemo.settings.json next to this script.

.EXAMPLE
    .\scripts\Invoke-HuntingQuery.ps1                           # AppOnly, everything from scripts\HuntingDemo.settings.json
.EXAMPLE
    .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated -Hours 24
.EXAMPLE
    .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated -TokenOutFile .\delegated-token.jwt
.EXAMPLE
    .\scripts\Invoke-HuntingQuery.ps1 -AuthMode AppOnly -TenantId <guid> -ClientId <guid> -Environment AzureGov

.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
.LINK
    https://learn.microsoft.com/defender-xdr/advanced-hunting-entraidsigninevents-table
.LINK
    https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod
.LINK
    https://learn.microsoft.com/graph/deployments
#>
[CmdletBinding()]
param(
    [ValidateSet('AppOnly', 'Delegated')]
    [string] $AuthMode = 'AppOnly',

    [string] $TenantId,

    [string] $ClientId,

    [securestring] $ClientSecret,

    [ValidateSet('Public', 'AzureGov')]
    [string] $Environment,

    [ValidateRange(1, 720)]
    [int] $Hours = 24,

    [string] $QueryFile,

    [string] $OutFile,

    [Alias('JwtOutFile')]
    [string] $TokenOutFile,

    [string] $SettingsFile = (Join-Path $PSScriptRoot 'HuntingDemo.settings.json')
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------------------------------------
# 0. Defaults from HuntingDemo.settings.json (JSON text -> object -> dot notation). Never holds the secret.
# ------------------------------------------------------------------------------------------------
if (Test-Path -Path $SettingsFile) {
    $settings = Get-Content -Path $SettingsFile -Raw | ConvertFrom-Json
    if (-not $TenantId    -and $settings.tenantId)    { $TenantId    = $settings.tenantId }
    if (-not $ClientId    -and $settings.clientId)    { $ClientId    = $settings.clientId }
    if (-not $Environment -and $settings.environment) { $Environment = $settings.environment }
    Write-Host "Defaults loaded from $SettingsFile" -ForegroundColor DarkGray
}

# ------------------------------------------------------------------------------------------------
# 1. Endpoints. REST = resources named by URIs; the host depends on the cloud, the path does not.
#    Order: explicit -Environment -> OpenID discovery for the tenant (GET, anonymous, JSON) -> Public.
# ------------------------------------------------------------------------------------------------
function Save-DemoAccessToken {
    param(
        [Parameter(Mandatory)]
        [string] $AccessToken,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent
    if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        throw "Token output directory does not exist: $parentPath"
    }

    [System.IO.File]::WriteAllText($resolvedPath, $AccessToken, [System.Text.UTF8Encoding]::new($false))
    Write-Host "JWT saved -> $resolvedPath" -ForegroundColor Yellow
    Write-Warning 'The JWT is a bearer credential. Do not share or commit it; delete it after the demo.'
}

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
                # REST call #0 - GET is the default verb, no token needed. The JSON tells us where this tenant lives.
                $oidc  = Invoke-RestMethod -Method Get -Uri $discoveryUri
                $mgEnv = switch ($oidc.msgraph_host) {
                    'graph.microsoft.us'     { 'USGov' }
                    'dod-graph.microsoft.us' { 'USGovDoD' }
                    default                  { 'Global' }
                }
                return [pscustomobject]@{
                    Environment   = $(if ($mgEnv -eq 'Global') { 'Public' } else { 'AzureGov' })
                    MgEnvironment = $mgEnv
                    LoginHost     = $c.LoginHost
                    TokenEndpoint = $oidc.token_endpoint                 # e.g. https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
                    GraphHost     = "https://$($oidc.msgraph_host)"      # graph.microsoft.com | graph.microsoft.us | dod-graph.microsoft.us
                    CloudInstance = $oidc.cloud_instance_name            # microsoftonline.com | microsoftonline.us
                    Source        = "OpenID discovery: GET $discoveryUri"
                }
            }
            catch { Write-Verbose "Discovery at $($c.LoginHost) failed: $($_.Exception.Message)" }
        }
    }

    # No tenant (or discovery failed): use the Graph PowerShell environment table when the module is present.
    $c  = $candidates[0]
    $mg = $null
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
        Import-Module Microsoft.Graph.Authentication
        $mg = Get-MgEnvironment | Where-Object Name -eq $c.MgEnvironment
    }
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

$ep  = Resolve-DemoEndpoints -TenantId $TenantId -Environment $Environment
$uri = "$($ep.GraphHost)/v1.0/security/runHuntingQuery"      # the resource (noun); POST is the verb (it's an action)

if (-not $OutFile) {
    $OutFile = Join-Path -Path (Get-Location) -ChildPath ("SignIns-Last{0}h-{1}.json" -f $Hours, (Get-Date -Format 'yyyyMMdd-HHmm'))
}

# ------------------------------------------------------------------------------------------------
# 2. The KQL. Same text you would paste into Defender > Advanced hunting.
# ------------------------------------------------------------------------------------------------
if ($QueryFile) {
    $kql = Get-Content -Path $QueryFile -Raw
}
else {
    $kql = @"
// Every user who signed in successfully during the last $Hours hours - one row per account
EntraIdSignInEvents
| where Timestamp > ago(${Hours}h)
| where ErrorCode == 0
| summarize LastSignIn  = max(Timestamp),
            SignInCount = count(),
            Apps        = make_set(Application, 5)
          by AccountUpn, AccountDisplayName
| order by LastSignIn desc
"@
}

# The request BODY: a hashtable is the PowerShell shape of a JSON object. ConvertTo-Json turns it into
# { "Query": "...", "Timespan": "P1D" }. Timespan is optional (ISO 8601 duration, default 30 days); the
# shorter of Timespan and the query's own ago() filter wins, so the KQL does the precise cut.
$timespan = 'P{0}D' -f [math]::Ceiling($Hours / 24)
$body = @{
    Query    = $kql
    Timespan = $timespan
} | ConvertTo-Json -Depth 3

Write-Host "`nEndpoints : $($ep.Source)" -ForegroundColor DarkGray
Write-Host "Cloud     : $($ep.Environment) ($($ep.MgEnvironment))  |  token: $($ep.TokenEndpoint)  |  graph: $($ep.GraphHost)" -ForegroundColor DarkGray
Write-Host "POST $uri" -ForegroundColor Cyan
Write-Host "Timespan $timespan  |  KQL window: last $Hours h  |  Auth: $AuthMode`n" -ForegroundColor DarkGray

$response = $null
$status   = $null
$hdrs     = $null

try {
    switch ($AuthMode) {

        'AppOnly' {
            # ----------------------------------------------------------------------------------------
            # 3a. Get a token - OAuth 2.0 client-credentials flow. The token endpoint is a REST API too.
            # ----------------------------------------------------------------------------------------
            if (-not $TenantId -or -not $ClientId) { throw 'AppOnly mode needs -TenantId and -ClientId (or HuntingDemo.settings.json from New-HuntingAppRegistration.ps1).' }
            if (-not $ClientSecret) {
                $ClientSecret = if ($env:HUNT_CLIENT_SECRET) { ConvertTo-SecureString -String $env:HUNT_CLIENT_SECRET -AsPlainText -Force }
                                else { Read-Host -Prompt 'Client secret' -AsSecureString }
            }

            $form = @{                                                    # hashtable -> application/x-www-form-urlencoded
                client_id     = $ClientId
                client_secret = ConvertFrom-SecureString -SecureString $ClientSecret -AsPlainText   # PS 7: decrypt only here
                scope         = "$($ep.GraphHost)/.default"               # '.default' = all app roles granted via admin consent
                grant_type    = 'client_credentials'                      # no user - the app is the identity
            }

            $tokenResponse = Invoke-RestMethod -Method Post -Uri $ep.TokenEndpoint -Body $form   # POST default = form-encoded (correct here)

            # The JSON answer is already deserialized: access_token (JWT), token_type (Bearer), expires_in (seconds)
            $token = ConvertTo-SecureString -String $tokenResponse.access_token -AsPlainText -Force
            Write-Host ("Token acquired: type={0}, expires in {1}s  (paste into https://jwt.ms to see aud / roles / exp)" -f $tokenResponse.token_type, $tokenResponse.expires_in) -ForegroundColor Green
            if ($TokenOutFile) { Save-DemoAccessToken -AccessToken $tokenResponse.access_token -Path $TokenOutFile }
            $form.Clear()                                                 # drop the plain-text secret as soon as possible

            # ----------------------------------------------------------------------------------------
            # 4a. Call Microsoft Graph - every switch explained.
            # ----------------------------------------------------------------------------------------
            $call = @{
                Method                  = 'Post'                          # verb: runHuntingQuery is an ACTION, so POST
                Uri                     = $uri                            # resource (host came from discovery / -Environment)
                Authentication          = 'Bearer'                        # PS 6+: emits  Authorization: Bearer <token>
                Token                   = $token                          # SecureString (https required)
                ContentType             = 'application/json; charset=utf-8'   # how Graph must parse the body
                Body                    = $body                           # JSON text
                StatusCodeVariable      = 'status'                        # PS 7: HTTP status code -> $status
                ResponseHeadersVariable = 'hdrs'                          # PS 6+: response headers  -> $hdrs
                SkipHttpErrorCheck      = $true                           # PS 7: return the JSON error body instead of throwing
                MaximumRetryCount       = 2                               # retry transient failures; a 429 honors Retry-After
                RetryIntervalSec        = 5
            }
            $response = Invoke-RestMethod @call                           # splatting: one hashtable = all the switches
        }

        'Delegated' {
            # ----------------------------------------------------------------------------------------
            # 3b/4b. Interactive sign-in via the Graph PowerShell SDK, then the same REST call.
            # First run in a tenant triggers the consent prompt; an admin must consent (or pre-consent).
            # ----------------------------------------------------------------------------------------
            if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
                throw 'Delegated mode needs the Microsoft.Graph.Authentication module: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
            }
            Import-Module Microsoft.Graph.Authentication

            $tokenResult = $null
            if ($TokenOutFile) {
                if (-not $TenantId -or -not $ClientId) {
                    throw 'Delegated token capture needs -TenantId and -ClientId (or HuntingDemo.settings.json from New-HuntingAppRegistration.ps1 -IncludeDelegatedScope).'
                }

                # Graph Authentication bundles MSAL but does not expose its token through Get-MgContext.
                $graphAuthModule = Get-Module -Name Microsoft.Graph.Authentication
                $msalPath = Join-Path $graphAuthModule.ModuleBase 'Dependencies\Core\Microsoft.Identity.Client.dll'
                if (-not (Test-Path -LiteralPath $msalPath)) {
                    $msalPath = Get-ChildItem -Path $graphAuthModule.ModuleBase -Recurse -File -Filter 'Microsoft.Identity.Client.dll' |
                        Select-Object -First 1 -ExpandProperty FullName
                }
                if (-not $msalPath) { throw 'Microsoft.Identity.Client.dll was not found in the Microsoft.Graph.Authentication module.' }
                if (-not ('Microsoft.Identity.Client.PublicClientApplicationBuilder' -as [type])) { Add-Type -Path $msalPath }

                $authority = "$(($ep.LoginHost).TrimEnd('/'))/$TenantId"
                $builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId).WithAuthority($authority).WithRedirectUri('http://localhost')
                $publicClient = $builder.Build()
                $interactive = $publicClient.AcquireTokenInteractive([string[]] @('ThreatHunting.Read.All')).WithPrompt([Microsoft.Identity.Client.Prompt]::SelectAccount)
                Write-Host 'Opening the browser for delegated sign-in and JWT capture ...' -ForegroundColor Cyan
                $tokenResult = $interactive.ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()

                Save-DemoAccessToken -AccessToken $tokenResult.AccessToken -Path $TokenOutFile
                $token = [securestring]::new()
                foreach ($character in $tokenResult.AccessToken.ToCharArray()) { $token.AppendChar($character) }
                $token.MakeReadOnly()
                Connect-MgGraph -AccessToken $token -Environment $ep.MgEnvironment -NoWelcome
            }
            else {
                $connect = @{ Scopes = 'ThreatHunting.Read.All'; Environment = $ep.MgEnvironment; NoWelcome = $true }
                if ($TenantId) { $connect.TenantId = $TenantId }
                if ($settings -and $settings.delegatedScope -and $ClientId) { $connect.ClientId = $ClientId }   # our own app, if it was set up for delegated use
                Connect-MgGraph @connect
            }

            # The signed-in context is the authority on which cloud we are in - re-read the Graph host from it.
            $ctx = Get-MgContext
            $mgEnvName = if ($ctx.Environment) { $ctx.Environment } else { $ep.MgEnvironment }
            $mgEnvObj  = Get-MgEnvironment | Where-Object Name -eq $mgEnvName
            if ($mgEnvObj) {
                $ep.GraphHost = $mgEnvObj.GraphEndpoint.TrimEnd('/')
                $ep.Source    = "Get-MgContext ($mgEnvName) -> Get-MgEnvironment"
                $uri = "$($ep.GraphHost)/v1.0/security/runHuntingQuery"
            }
            $signedInAccount = if ($tokenResult -and $tokenResult.Account) { $tokenResult.Account.Username } else { $ctx.Account }
            $signedInScopes = if ($tokenResult -and $tokenResult.Scopes) { $tokenResult.Scopes } else { $ctx.Scopes }
            Write-Host ("Signed in as {0}  |  environment {1}  |  scopes: {2}" -f $signedInAccount, $mgEnvName, ($signedInScopes -join ', ')) -ForegroundColor Green

            # Invoke-MgGraphRequest = Invoke-RestMethod with the token handled by MSAL. Same verb, URI and body.
            $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body `
                -ContentType 'application/json; charset=utf-8' -OutputType PSObject
            $status = 200                                                  # the SDK throws on any non-success status
        }
    }
}
catch {
    # Token-endpoint, sign-in and transport errors land here. Entra ID errors are JSON too:
    # { "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret ..." }
    Write-Host "`nRequest failed." -ForegroundColor Red
    if ($_.Exception.Response) { Write-Host ("HTTP {0}" -f [int]$_.Exception.Response.StatusCode) -ForegroundColor Red }
    if ($_.ErrorDetails.Message) {
        try   { $_.ErrorDetails.Message | ConvertFrom-Json | ConvertTo-Json -Depth 5 | Write-Host }
        catch { Write-Host $_.ErrorDetails.Message }
    }
    else { Write-Host $_.Exception.Message }
    Write-Host "`n401 = no/invalid token   403 = token lacks ThreatHunting.Read.All (admin consent?)   429 = throttled (Retry-After)" -ForegroundColor DarkGray
    exit 1
}

# ------------------------------------------------------------------------------------------------
# 5. Status code first. With -SkipHttpErrorCheck a 4xx/5xx does not throw - the JSON error body is in
#    $response: { "error": { "code": "...", "message": "...", "innerError": { "request-id": "..." } } }
# ------------------------------------------------------------------------------------------------
if ($status -ge 400) {
    Write-Host ("HTTP {0}" -f $status) -ForegroundColor Red
    $response | ConvertTo-Json -Depth 5 | Write-Host
    Write-Host "`n401 = no/invalid token   403 = token lacks ThreatHunting.Read.All (admin consent?)   429 = throttled (Retry-After)" -ForegroundColor DarkGray
    exit 1
}

# ------------------------------------------------------------------------------------------------
# 6. The response body is huntingQueryResults: { schema: [ {name,type} ... ], results: [ {row} ... ] }
# ------------------------------------------------------------------------------------------------
$rows = @($response.results).Count
$requestId = if ($hdrs -and $hdrs['request-id']) { $hdrs['request-id'] -join '' } else { 'n/a' }
Write-Host ("`nHTTP {0}  |  {1} row(s)  |  request-id {2}`n" -f $status, $rows, $requestId) -ForegroundColor Cyan

Write-Host 'schema  = ARRAY OF OBJECTS (one per column)' -ForegroundColor DarkGray
$response.schema | Format-Table name, type -AutoSize | Out-String | Write-Host

Write-Host 'results = ARRAY OF OBJECTS (one per user) - first 10' -ForegroundColor DarkGray
$response.results | Select-Object -First 10 |
    Format-Table AccountUpn, AccountDisplayName, LastSignIn, SignInCount, Apps -AutoSize | Out-String | Write-Host

# ------------------------------------------------------------------------------------------------
# 7. Objects -> JSON text -> file. -Depth 10 keeps nested arrays (Apps) intact; default depth is 2.
# ------------------------------------------------------------------------------------------------
$response | ConvertTo-Json -Depth 10 | Set-Content -Path $OutFile -Encoding utf8     # PS 7: UTF-8 without BOM
Write-Host "Saved -> $OutFile" -ForegroundColor Green

# Round trip: JSON text -> objects -> dot notation
$check = Get-Content -Path $OutFile -Raw | ConvertFrom-Json
if ($rows -gt 0) {
    Write-Host ("First user in the file: {0}  (last sign-in {1})" -f $check.results[0].AccountUpn, $check.results[0].LastSignIn) -ForegroundColor DarkGray
}
