# Finding OAuth Resource Identifiers and Token Audiences

**BLUF:** The authoritative way is to consult the API’s authentication documentation for its **resource identifier / App ID URI**, then request:

```text
<resource-identifier>/.default
```

Do **not** assume the API hostname is always its token audience. It often is related, but it is not guaranteed to be the same.

## What you are looking for

For client-credentials authentication, you need the API’s **resource identifier**—also called:

- **Application ID URI**
- **Identifier URI**
- **Resource URI**
- sometimes simply **audience**

Then request:

```text
scope=<resource-identifier>/.default
```

Example:

```text
Microsoft Graph resource identifier:
https://graph.microsoft.com

Token request scope:
https://graph.microsoft.com/.default
```

The `.default` syntax means “issue a token for this API, containing the application roles already granted to this workload for this API.”

---

## Recommended process

### 1. Start with the API’s official authentication documentation

Look for a section titled something like:

```text
Authentication
Authorization
Obtain an access token
OAuth 2.0
Client credentials
App-only authentication
```

You want the documented token-resource/scope value, **not merely the REST endpoint**.

Examples:

| API | API endpoint example | Scope/resource request |
| --- | --- | --- |
| Microsoft Graph | `https://graph.microsoft.com/v1.0/...` | `https://graph.microsoft.com/.default` |
| Exchange Online | Exchange Online PowerShell / Exchange APIs | `https://outlook.office365.com/.default` |
| Azure Resource Manager | `https://management.azure.com/...` | `https://management.azure.com//.default` |
| Custom internal API | `https://api.contoso.example/...` | Usually its configured App ID URI, such as `api://<api-client-id>/.default` |

For Azure Resource Manager, the resource identifier ends in `/`, so its `/.default` format produces a double slash:

```text
https://management.azure.com//.default
```

That behavior is documented for resources whose identifier URI already ends with a slash.

---

## 2. For an internal/custom API, inspect **Expose an API**

If your organization owns the API:

1. Go to **Entra admin center** → **App registrations**.
2. Select the application registration representing the **API**, not the calling workload.
3. Select **Expose an API**.
4. Find the **Application ID URI**.

Typical values are:

```text
api://<api-client-id>
```

or:

```text
api://<tenant-id>/<api-client-id>
```

or an HTTPS URI such as:

```text
https://api.contoso.example
```

Use that exact value to form the request scope:

```powershell
$scope = "api://<api-client-id>/.default"
```

The Application ID URI—also called `identifierUris`—is the resource API identifier and serves as the prefix for that API’s OAuth scopes.

---

## 3. Inspect the API’s service principal programmatically

If you know the API’s Entra application/client ID, find its tenant-local service principal:

```powershell
$apiAppId = "<resource-api-client-id>"

$apiSp = Get-MgServicePrincipal `
    -Filter "appId eq '$apiAppId'" `
    -Property Id, AppId, DisplayName, ServicePrincipalNames, AppRoles

$apiSp | Select-Object Id, AppId, DisplayName, ServicePrincipalNames
```

The important fields are:

```powershell
$apiSp.Id
# Tenant-local service principal object ID.
# Use this as resourceId when assigning an app role.

$apiSp.AppId
# API's client/application ID.

$apiSp.ServicePrincipalNames
# Includes identifiers used to reference the API/resource.
```

To view application roles available for managed identities or other app-only callers:

```powershell
$apiSp.AppRoles |
    Where-Object {
        $_.AllowedMemberTypes -contains "Application"
    } |
    Select-Object Value, DisplayName, Id
```

If the role you need appears there, then:

```text
resourceId = $apiSp.Id
appRoleId  = the matching role's Id
```

The `servicePrincipalNames` collection contains identifier URIs copied from the associated application and can be used to identify permissions exposed by the API.

---

## 4. Request a test token and inspect its `aud` claim

After you have the documented scope/resource URI, request a token and inspect the token payload in an approved lab environment.

For a v2 endpoint token request:

```powershell
$token = Invoke-RestMethod `
    -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{
        client_id     = $clientId
        client_secret = $clientSecret
        grant_type    = "client_credentials"
        scope         = "<resource-identifier>/.default"
    }
```

The token’s `aud` claim identifies the intended API audience.

```json
{
  "aud": "...",
  "roles": [
    "..."
  ]
}
```

Do not expect `aud` always to be the same literal URI you used in `scope`. In a v2 access token, Entra ID commonly emits the **API’s client ID** as the audience; in v1 tokens, it can be a client ID or a resource/App ID URI. The API itself validates that the token’s `aud` matches an audience it accepts.

---

## The key distinction

There are three related but different things:

```text
API endpoint:
    Where you send the HTTP request.

Resource identifier / App ID URI:
    What you request a token FOR.

Token aud claim:
    What Entra ID puts in the issued token to identify its intended recipient.
```

Example:

```text
Microsoft Graph endpoint:
    https://graph.microsoft.com/v1.0/users

Microsoft Graph resource identifier:
    https://graph.microsoft.com

Requested scope:
    https://graph.microsoft.com/.default

Token audience:
    Microsoft Graph's accepted audience value
```

For a custom API:

```text
Custom API endpoint:
    https://api.contoso.example/v1/reports

Custom API App ID URI:
    api://12345678-1234-1234-1234-123456789abc

Requested scope:
    api://12345678-1234-1234-1234-123456789abc/.default
```

## Practical checklist

Before requesting a token for an unfamiliar API, determine:

```text
1. What API endpoint will I call?
2. What resource identifier / App ID URI does its documentation specify?
3. Does the resource service principal expose an Application app role?
4. Has that app role been assigned to my app or managed identity?
5. Does my acquired token have the expected aud and roles claims?
6. Does the API accept that token?
```

If any answer is unknown, use the API’s official authentication documentation first; token audience/resource values are API-specific and should not be inferred solely from the endpoint hostname.
