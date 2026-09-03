# Understanding Microsoft Graph App-Role Assignment IDs

**BLUF:** `resourceId` identifies the **service principal that owns/defines the app role** you are assigning. Because `ThreatHunting.Read.All` is a Microsoft Graph application permission, its owner is the **Microsoft Graph service principal** in your tenant.

Think of the assignment as a three-part statement:

```text
Grant [appRoleId]
from  [resourceId]
to    [principalId]
```

For your example:

```text
Grant ThreatHunting.Read.All
from  Microsoft Graph
to    managed identity
```

## The three values

| Property | What it identifies | Your scenario |
| --- | --- | --- |
| `principalId` | The identity receiving the permission. | The managed identity’s service principal object ID: `$managedIdentitySp.Id` |
| `resourceId` | The API/service that exposes and owns the permission. | Microsoft Graph’s service principal object ID: `$graphSp.Id` |
| `appRoleId` | The specific application permission role defined by that API/service. | The ID of Graph’s `ThreatHunting.Read.All` app role: `$graphAppRole.Id` |

## Relationship diagram

```text
┌──────────────────────────────────────────────────────────┐
│ Managed Identity Service Principal                        │
│                                                          │
│ Object ID: $managedIdentitySp.Id                          │
│ This is the PRINCIPAL receiving the permission.           │
└─────────────────────────┬────────────────────────────────┘
                          │
                          │ App role assignment
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ Microsoft Graph Service Principal                         │
│                                                          │
│ Object ID: $graphSp.Id                                   │
│ This is the RESOURCE that defines the permission.         │
│                                                          │
│ App roles it exposes include:                             │
│   • ThreatHunting.Read.All                               │
│   • User.Read.All                                        │
│   • Group.Read.All                                       │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ Microsoft Graph App Role                                  │
│                                                          │
│ ID: $graphAppRole.Id                                      │
│ Value: ThreatHunting.Read.All                             │
│ This is the specific permission being assigned.           │
└──────────────────────────────────────────────────────────┘
```

## Why `appRoleId` alone is not enough

An app role ID only has meaning in the context of the application/API that defines it.

For example, your organization might have two APIs:

```text
Microsoft Graph:
    App role: ThreatHunting.Read.All
    App role ID: <Graph role GUID>

Internal Reporting API:
    App role: Reports.Read.All
    App role ID: <Internal API role GUID>
```

The Entra ID directory must know:

1. **Who receives the role?**
   The managed identity: `principalId`.

2. **Which API owns the role?**
   Microsoft Graph: `resourceId`.

3. **Which role from that API?**
   `ThreatHunting.Read.All`: `appRoleId`.

Without `resourceId`, Entra ID cannot reliably determine which resource application’s app-role catalog should be used to interpret and validate the `appRoleId`.

## Why the Graph service principal is used—not the Graph application ID

There are two related Microsoft Graph identifiers:

| Identifier | Value / use |
| --- | --- |
| Microsoft Graph **application (client) ID** | `00000003-0000-0000-c000-000000000000`; same across tenants; used to locate Graph. |
| Microsoft Graph **service principal object ID** | Unique to your Entra tenant; used as the `resourceId` in an app-role assignment. |

You use the well-known Graph app ID only to find the tenant-local Graph service principal:

```powershell
$graphApplicationId = "00000003-0000-0000-c000-000000000000"

$graphSp = Get-MgServicePrincipal `
    -Filter "appId eq '$graphApplicationId'"
```

Then:

```powershell
$graphSp.Id
```

is the tenant-specific service principal object ID and becomes the `resourceId`.

## Read the assignment in plain English

This command:

```powershell
$params = @{
    principalId = $managedIdentitySp.Id
    resourceId  = $graphSp.Id
    appRoleId   = $graphAppRole.Id
}

New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $managedIdentitySp.Id `
    -BodyParameter $params
```

means:

```text
Create an app-role assignment on this managed identity service principal.

Principal receiving role:
    $managedIdentitySp.Id

Resource API that defines the role:
    $graphSp.Id

Specific role being granted:
    $graphAppRole.Id
    = ThreatHunting.Read.All
```

After assignment, when the managed identity requests a token for Microsoft Graph:

```text
https://graph.microsoft.com/.default
```

Entra ID recognizes that the managed identity has an app-role assignment from the Microsoft Graph resource service principal. It issues a Graph access token with a `roles` claim containing:

```json
{
  "roles": [
    "ThreatHunting.Read.All"
  ]
}
```

That `roles` claim is what Microsoft Graph evaluates when it receives the managed identity’s request.
