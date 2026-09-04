# Entra ID and Microsoft Graph App-Only Authentication

## 1. Client Secret Authentication and Scopes

### Question

When I create an application registration and map the Graph Security API with roles like `ThreatHunting.Read.All`, grant admin consent, create a secret, and supply the tenant ID, client ID, and client secret, do I need to specify the scope in PowerShell or is that only under delegation?

### Answer

For an app-only connection using a client secret—OAuth **client credentials** flow—you do specify a scope when acquiring the token. However, use the resource’s `/.default` scope, not the individual application permission name.

```powershell
$scope = "https://graph.microsoft.com/.default"
```

The `/.default` scope tells Entra ID to issue an access token containing the Microsoft Graph **application permissions** that are already configured on the app registration and have received administrator consent—for example, `ThreatHunting.Read.All`.

Do **not** request the individual application permission in the token request:

```text
ThreatHunting.Read.All
```

### MSAL.PS Example

```powershell
$token = Get-MsalToken `
    -TenantId $tenantId `
    -ClientId $clientId `
    -ClientSecret (ConvertTo-SecureString $clientSecret -AsPlainText -Force) `
    -Scopes "https://graph.microsoft.com/.default"

$headers = @{
    Authorization = "Bearer $($token.AccessToken)"
}
```

### Direct v2 Token Endpoint Example

```powershell
$body = @{
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
    grant_type    = "client_credentials"
}

$token = Invoke-RestMethod `
    -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $body

$headers = @{
    Authorization = "Bearer $($token.access_token)"
}
```

### Delegated versus Application Permission Scope Behavior

| Flow | Token request scope behavior |
| --- | --- |
| **Client credentials / application permissions** | Request `https://graph.microsoft.com/.default`. The token contains a `roles` claim. No user is involved. |
| **Delegated permissions** | Request named delegated scopes, such as `User.Read` or `ThreatHunting.Read.All`. The token contains an `scp` claim. A signed-in user is involved. |

`ThreatHunting.Read.All` is available as both an application and delegated permission. When using client ID and client secret authentication, ensure that it is selected under **Application permissions**, rather than only under Delegated permissions, and that tenant admin consent has been granted.

In this workshop, delegated mode uses Windows Web Account Manager (WAM) with the app registration's public-client broker redirect. It uses neither the training certificate nor the client secret; those credentials are exclusive to the two app-only demonstrations.

---

## 2. MSAL.PS versus the v2 Client-Credentials Endpoint

### Bottom Line

There is no authorization advantage to MSAL.PS compared with posting directly to the Entra ID **v2.0 token endpoint**. Both use the client-credentials flow and receive the same category of app-only access token.

For a new PowerShell automation, generally choose one of the following:

1. **Microsoft Graph PowerShell SDK** (`Connect-MgGraph`) if the script will primarily call Microsoft Graph.
2. A direct `Invoke-RestMethod` request to Entra ID if you want minimal dependencies and full HTTP-level control.

MSAL.PS is convenient but is not a Microsoft-supported PowerShell module. Avoid adding it as a new production dependency unless it is already approved and deployed in the environment.

### Comparison

| Option | Advantages | Tradeoffs / best use |
| --- | --- | --- |
| **Direct v2 token request** | No module dependency; transparent OAuth behavior; easy to troubleshoot raw HTTP requests and responses. | You manage token expiration, headers, retries, paging, and secure secret handling. Good for small, controlled scripts. |
| **MSAL.PS** | Convenient token-acquisition syntax; uses underlying MSAL.NET functionality. | Extra dependency; not a Microsoft-supported PowerShell module. |
| **Microsoft Graph PowerShell SDK** | Microsoft-supported; uses MSAL underneath; includes Graph cmdlets, paging support, and `Invoke-MgGraphRequest`. | Larger module footprint; generated cmdlets can be verbose. |
| **MSAL.NET directly** | Strong choice for developed applications or mature internal modules needing robust token-cache behavior. | More code and dependency management than most scripts need. |

### Microsoft Graph PowerShell SDK with a Client Secret

```powershell
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force

$credential = [pscredential]::new($clientId, $secureSecret)

Connect-MgGraph `
    -TenantId $tenantId `
    -ClientSecretCredential $credential `
    -NoWelcome
```

Then make a Graph call:

```powershell
Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
    -Body @{
        Query = "DeviceEvents | take 10"
    }
```

When using `Connect-MgGraph` with app-only authentication, the SDK handles the Microsoft Graph `/.default` request. You do not separately specify `-Scopes` for application permissions.

### Direct REST Pattern

```powershell
$token = Invoke-RestMethod `
    -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{
        client_id     = $clientId
        client_secret = $clientSecret
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
    }

$headers = @{
    Authorization = "Bearer $($token.access_token)"
}
```

For scheduled or long-lived automation, prefer a certificate or managed identity over a client secret where feasible.

---

## 3. Recommended Learning Progression

A useful teaching progression for programmatic Microsoft Graph authentication is:

```text
Client Secret → Certificate → Managed Identity
```

The OAuth flow remains an app-only client-credentials flow. The credential used to prove the workload’s identity changes.

| Credential type | How it works |
| --- | --- |
| **Client secret** | The application sends a secret to Entra ID. |
| **Certificate** | The application signs a client assertion with its private key. Entra ID has the public certificate. |
| **Managed identity** | Azure provides the identity and token. No secret or certificate is distributed to the workload. |

---

## 4. Certificate-Based App-Only Authentication

### Certificate versus Client Secret

| Client secret | Certificate |
| --- | --- |
| The app sends a secret to Entra ID. | The app proves it possesses a certificate private key. |
| The secret must be stored and rotated. | The private key stays on the workload host and the certificate must be renewed/rotated. |
| Straightforward for basic demonstrations. | Generally preferable for traditional unattended automation. |
| Entra ID stores the secret value. | Entra ID receives and stores only the public certificate. |

The app registration must still have the required Microsoft Graph **Application permissions**, such as `ThreatHunting.Read.All`, and those permissions must receive admin consent.

### Create the Workshop Certificate on Windows

The workshop setup creates and registers the certificate automatically:

```powershell
.\scripts\New-HuntingAppRegistration.ps1 `
        -IncludeDelegatedScope `
    -CertificateValidityMonths 12
```

The script uses .NET `CertificateRequest` to create an RSA-4096/SHA-256 self-signed certificate in memory. It then imports the key as non-exportable and copies the certificate into Current User > Personal through .NET `X509Store.Add()`.

The certificate name is intentionally readable and matches the app registration:

```text
Graph Security API - Hunting Demo - <alias> - <suffix> - TRAINING
```

The console’s **TRAINING ONLY CERTIFICATE DETAILS** block supplies exact correlation:

- App registration display name
- Application (client) ID
- Application object ID
- Tenant ID
- Certificate subject, friendly name, key ID and thumbprints
- `Cert:\CurrentUser\My` store location and 12-month validity (adjustable from 1–24 months)
- `TRAINING ONLY - SELF-SIGNED - NOT FOR PRODUCTION` purpose

The script sends only the Base64 public certificate to `PATCH /applications/{id}` as an `AsymmetricX509Cert` / `Verify` key credential. It does not export a `.cer` or `.pfx`, write a private key to disk, or place private-key material in `HuntingDemo.settings.json`; common certificate and key extensions are also Git-ignored.

### Confirm the Registered Public Certificate

1. Open **Microsoft Entra admin center** > **App registrations**.
2. Select the matching `Graph Security API - Hunting Demo - ...` app.
3. Select **Certificates & secrets** > **Certificates**.
4. Match `<app registration name> - TRAINING`, its thumbprint and expiration to the setup output.

> Entra ID receives only the public certificate. The workload’s non-exportable private key remains in the local Current User certificate store for this workshop.

### Where to Install the Certificate

#### Student Lab or Interactive User

Use the current user Personal certificate store:

```text
Cert:\CurrentUser\My
```

This is simplest for a classroom environment and interactive PowerShell use.

#### Server, Scheduled Task, or Service Account

Use the Local Machine Personal certificate store:

```text
Cert:\LocalMachine\My
```

Then grant the account that actually runs the scheduled task or service **read permission to the certificate private key**.

Installing the certificate is not sufficient if the runtime account cannot access the private key.

For production, use an organization-approved PKI and certificate lifecycle/renewal process rather than an ad hoc self-signed certificate.

### Authenticate to Microsoft Graph with a Certificate

The demo reads the correlated thumbprint from `HuntingDemo.settings.json` and copies the complete resulting JWT to the clipboard:

```powershell
.\scripts\Invoke-HuntingQuery.ps1 -AuthMode Certificate
```

A successful certificate token is app-only and contains:

```text
roles: [ "ThreatHunting.Read.All" ]
```

The certificate changes how the app proves its identity, not the app identity, permission, token audience, or `roles` claim. Paste the clipboard directly into <https://jwt.ms> to compare it with the secret-based app-only token.

Override the stored thumbprint only when needed:

```powershell
.\scripts\Invoke-HuntingQuery.ps1 `
    -AuthMode Certificate `
    -CertificateThumbprint '<thumbprint>'
```

---

## 5. Managed Identity and Microsoft Graph Application Permissions

A managed identity is represented in Entra ID by a **service principal**.

Granting that identity Microsoft Graph application permissions is therefore an **app role assignment**.

```text
Managed identity service principal
        ↓ receives an app-role assignment
Microsoft Graph service principal
        ↓ defines the application role
ThreatHunting.Read.All
```

You do not create an app registration, client secret, or certificate for a managed identity.

First enable a system-assigned or user-assigned managed identity on the Azure workload. Then assign Microsoft Graph application permissions to that managed identity’s service principal.

> The following permission-assignment commands should be run by an appropriately privileged Entra administrator. The managed identity should not grant its own permissions.

### Assign `ThreatHunting.Read.All` to a Managed Identity

```powershell
# One-time Entra administrator action.
Connect-MgGraph `
    -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" `
    -NoWelcome

# The managed identity's principal ID / service principal object ID.
# Obtain it from the Azure resource's Identity blade, or from the
# user-assigned managed identity resource.
$managedIdentityPrincipalId = "<managed-identity-principal-object-id>"

# Microsoft Graph's well-known application/client ID.
$graphApplicationId = "00000003-0000-0000-c000-000000000000"

# Locate the managed identity service principal.
$managedIdentitySp = Get-MgServicePrincipal `
    -ServicePrincipalId $managedIdentityPrincipalId

# Locate Microsoft Graph's service principal in the tenant.
$graphSp = Get-MgServicePrincipal `
    -Filter "appId eq '$graphApplicationId'"

# Locate the Graph APPLICATION role, not the delegated scope.
$graphAppRole = $graphSp.AppRoles | Where-Object {
    $_.Value -eq "ThreatHunting.Read.All" -and
    $_.AllowedMemberTypes -contains "Application"
}

if (-not $graphAppRole) {
    throw "Microsoft Graph application role ThreatHunting.Read.All was not found."
}

# Assign the Microsoft Graph app role to the managed identity.
$params = @{
    principalId = $managedIdentitySp.Id
    resourceId  = $graphSp.Id
    appRoleId   = $graphAppRole.Id
}

New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $managedIdentitySp.Id `
    -BodyParameter $params
```

### Meaning of the Role-Assignment Values

| Identifier | Meaning |
| --- | --- |
| `principalId` | The service principal receiving the permission: the managed identity. |
| `resourceId` | The service principal exposing the permission: Microsoft Graph. |
| `appRoleId` | The application permission role: `ThreatHunting.Read.All`. |

### Verify the Role Assignment

```powershell
Get-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $managedIdentitySp.Id |
    Where-Object {
        $_.ResourceId -eq $graphSp.Id -and
        $_.AppRoleId -eq $graphAppRole.Id
    } |
    Format-List Id, PrincipalDisplayName, ResourceDisplayName, AppRoleId
```

### Authenticate from an Azure Workload with Managed Identity

Run these commands from the Azure resource that has the managed identity.

#### System-Assigned Managed Identity

```powershell
Connect-MgGraph -Identity -NoWelcome

Get-MgContext
```

#### User-Assigned Managed Identity

```powershell
Connect-MgGraph `
    -Identity `
    -ClientId "<user-assigned-managed-identity-client-id>" `
    -NoWelcome

Get-MgContext
```

Then call Graph normally:

```powershell
Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
    -Body @{
        Query = "DeviceEvents | take 10"
    }
```

---

## 6. Key Takeaways

1. **Client secrets** are appropriate for teaching OAuth basics, but require protected storage and rotation.
2. **Certificates** are generally stronger for traditional unattended workloads because the private key can remain local to the host.
3. **Managed identities** are preferable for Azure-hosted workloads because Azure manages the identity, credential, and token acquisition.
4. Microsoft Graph **application permissions** such as `ThreatHunting.Read.All` are granted as **app roles**.
5. Client-credentials token requests target Microsoft Graph with:

   ```text
   https://graph.microsoft.com/.default
   ```

6. Delegated permissions use named scopes and a signed-in user; application permissions use `/.default` and no user context.
7. Apply least privilege, grant only required permissions, and periodically review service-principal app-role assignments.
