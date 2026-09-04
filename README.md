# REST APIs, JSON & the Microsoft Graph Security API

> A hands-on training kit for Cloud Solution Architects: a 20-slide deck, three interactive request-flow simulations, an "Anatomy of a JSON Object" diagram, and a live PowerShell 7 demo that runs a Microsoft Defender XDR advanced hunting query through the **Microsoft Graph Security API** (`POST /security/runHuntingQuery`) using the `ThreatHunting.Read.All` permission — app-only *and* delegated, so learners experience the difference.

![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph v1.0](https://img.shields.io/badge/Microsoft%20Graph-v1.0-0078D4)
![Defender XDR](https://img.shields.io/badge/Defender%20XDR-Advanced%20hunting-107C10)
![Clouds](https://img.shields.io/badge/Clouds-Public%20%7C%20Azure%20Government-6264A7)

---

## What you will learn

- Why REST APIs are the bedrock of Cloud, GenAI, web applications and MCP — and what **REST** (REpresentational State Transfer), **API** and **JSON** actually stand for.
- The anatomy of a REST call: verb · URI · headers · body → status code · headers · body.
- The anatomy of JSON: objects, key/value pairs, the six data types, arrays of objects, objects within objects — and how each maps to PowerShell 7.
- How the Graph Security API exposes advanced hunting, what `ThreatHunting.Read.All` grants, and why **admin consent** exists, who can give it and how (portal, URL, prompt, or programmatically).
- How an OAuth 2.0 token flows from an app registration to a `200 OK`.
- `Invoke-RestMethod` switch by switch: `-Method`, `-Uri`, `-Authentication Bearer -Token`, `-ContentType`, `-Body`, `-StatusCodeVariable`, `-ResponseHeadersVariable`, `-SkipHttpErrorCheck`, `-MaximumRetryCount`.

## What is in this repository

| File | Purpose |
| --- | --- |
| [`REST-APIs-JSON-Graph-Security-API.html`](class_content/REST-APIs-JSON-Graph-Security-API.html) | The 20-slide deck. One self-contained HTML file (Microsoft dark Fluent style) — open in any browser, present with **F**, speaker notes with **N**. |
| [`Sim-App-Registration-Admin-Consent.html`](class_content/Sim-App-Registration-Admin-Consent.html) | 13-step simulation of creating the app registration, client secret, service principal, and programmatic admin consent through Microsoft Graph. |
| [`Sim-AppOnly-Client-Credentials.html`](class_content/Sim-AppOnly-Client-Credentials.html) | 12-step simulation of OpenID discovery, the OAuth 2.0 client-credentials token request, `runHuntingQuery`, error boundaries, and JSON output. |
| [`Sim-Delegated-Sign-In-Consent.html`](class_content/Sim-Delegated-Sign-In-Consent.html) | 13-step simulation of delegated browser sign-in, admin consent, authorization-code redemption, the `scp` claim, and the Graph hunting call. |
| [`Identity_101.md`](extras/Identity_101.md) | Supplemental primer on app-only scopes, client secrets, certificates, managed identities, and Microsoft Graph application permissions. |
| [`Identity_102.md`](extras/Identity_102.md) | Deep dive into `principalId`, `resourceId`, and `appRoleId` for managed-identity app-role assignments. |
| [`Identity_103.md`](extras/Identity_103.md) | Guide to identifying an API resource URI, forming its `/.default` scope, and validating token audience and roles. |
| [`JSON-Anatomy-Diagram.svg`](images/JSON-Anatomy-Diagram.svg) · [`JSON-Anatomy-Diagram.png`](images/JSON-Anatomy-Diagram.png) | Stand-alone diagram of a JSON object: keys/values, string, number, boolean, null, array, array of objects, nested object, with PowerShell 7 equivalents. Also embedded on slide 8. |
| [`rest-api-demo-flow-neon.svg`](images/rest-api-demo-flow-neon.svg) · [`rest-api-demo-flow-neon.png`](images/rest-api-demo-flow-neon.png) | Dark-neon sequence diagram of the complete demo flow: endpoint discovery, OAuth token request, Graph hunting query, JSON response, and local persistence. |
| [`New-HuntingAppRegistration.ps1`](scripts/New-HuntingAppRegistration.ps1) | One-time setup. Creates a uniquely named app registration (`Graph Security API - Hunting Demo - <alias> - <6 random characters>`) **programmatically through Graph REST calls**: `ThreatHunting.Read.All` (Application), tenant-wide admin consent, a 12-month client secret, and writes `scripts/HuntingDemo.settings.json`. |
| [`Invoke-HuntingQuery.ps1`](scripts/Invoke-HuntingQuery.ps1) | The live demo. `-AuthMode AppOnly` (raw `Invoke-RestMethod`: discovery → token → Graph) or `-AuthMode Delegated` (`Connect-MgGraph` → `Invoke-MgGraphRequest`). Writes the JSON response to a file. |
| [`SignIns-Last24h.kql`](SignIns-Last24h.kql) | The hunting query: every user who signed in successfully in the last 24 hours, one row per account. Runs unchanged in Defender > Advanced hunting. |
| [`README-Facilitator-Notes.md`](README-Facilitator-Notes.md) | Presenter runbook: slide outline, day-before checklist, live-demo script, sources and facts to state precisely. |

## Prerequisites

| Area | Requirement |
| --- | --- |
| Tenant & licensing | Microsoft Defender XDR. The `EntraIdSignInEvents` table requires **Microsoft Entra ID P2** (fallback: `IdentityLogonEvents`, see the end of the `.kql`). |
| Role to run the setup script | **Privileged Role Administrator** or Global Administrator. Cloud Application Administrator can create the app but *cannot* consent to Microsoft Graph application permissions. |
| Role to run the delegated demo | Any user an admin has consented for — or an admin, who will see "Consent on behalf of your organization" on first run. |
| Tooling | **PowerShell 7.0+** (`pwsh`). Windows PowerShell 5.1 lacks `-Authentication`, `-Token`, `-StatusCodeVariable`, `-SkipHttpErrorCheck` and `ConvertFrom-SecureString -AsPlainText`. |
| Module | `Microsoft.Graph.Authentication` (setup script and Delegated mode): `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` |
| Network | `login.microsoftonline.com` and `graph.microsoft.com` — or the `.us` equivalents for Azure Government (discovered automatically, see below). |

## Quick start

```powershell
# 1. Clone
git clone https://github.com/dcodev1702/REST-API-Class-L200.git
cd REST-API-Class-L200

# 2. One-time: create the app registration, grant admin consent, issue a 12-month secret
#    (sign in as Privileged Role Administrator; add -TenantId <id-or-domain> if you have several tenants)
.\scripts\New-HuntingAppRegistration.ps1 -PreviewName # optional; shows the generated name without creating anything
.\scripts\New-HuntingAppRegistration.ps1              # add -IncludeDelegatedScope to capture the delegated JWT
#    -> names the app Graph Security API - Hunting Demo - <signed-in alias> - <6 random characters>
#    -> prints Tenant ID, Client ID and the SECRET (shown once - copy it now)
#    -> writes scripts\HuntingDemo.settings.json (identifiers + endpoints, never the secret)

# 3. Keep the secret out of the scripts for the session
$env:HUNT_CLIENT_SECRET = '<paste the secret>'        # or skip this and let the script prompt

# 4. Run the demo - app-only (OAuth 2.0 client credentials, pure REST)
.\scripts\Invoke-HuntingQuery.ps1 -TokenOutFile .\app-only-token.jwt

# 5. Run it again - delegated (requires setup with -IncludeDelegatedScope when saving the JWT)
.\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated -TokenOutFile .\delegated-token.jwt

# 6. Look at what came back
Get-Content .\SignIns-Last24h-*.json -Raw | ConvertFrom-Json | Select-Object -ExpandProperty results | Format-Table
```

Allow 1–2 minutes between step 2 and step 4 for directory replication.

## How the demo works

Three REST calls, all visible in the console output:

[![Dark-neon sequence diagram of the REST API demo flow](images/rest-api-demo-flow-neon.png)](images/rest-api-demo-flow-neon.svg)

| Step | Call | REST concept it teaches |
| --- | --- | --- |
| 0 | `GET …/.well-known/openid-configuration` | GET is the default verb; no auth; JSON back; the cloud is *discovered*, not hard-coded. |
| 1 | `POST {token_endpoint}` | A hashtable body is form-encoded (the POST default); `.default` scope = every app role granted by admin consent. |
| 2 | `POST /security/runHuntingQuery` | An *action* is a POST even though it only reads; Bearer header; JSON body; `schema[]` + `results[]` = arrays of objects. |
| 3 | `ConvertTo-Json -Depth 10` | The default depth of 2 truncates nested arrays (`Apps`) — the number-one JSON trap in PowerShell. |

Delegated mode replaces steps 0–1 with `Connect-MgGraph -Scopes 'ThreatHunting.Read.All'` (MSAL handles the token and shows the consent prompt) and issues step 2 with `Invoke-MgGraphRequest` — same verb, URI and body. When `-TokenOutFile` is supplied, the script uses the Microsoft Authentication Library bundled with the Graph module to acquire and save the same delegated token before passing it to `Connect-MgGraph`.

## Public vs Azure Government — how endpoints are resolved

Nothing is hard-coded to a cloud. Both scripts share the same `Resolve-DemoEndpoints` logic:

1. **`-Environment Public | AzureGov`** when passed — URLs come from the Graph PowerShell environment table (`Get-MgEnvironment`: `Global` / `USGov`) when the SDK is installed, otherwise from a two-row built-in map.
2. **Otherwise, discovery from the tenant** — the OpenID Connect document above returns `token_endpoint` and `msgraph_host`: `graph.microsoft.com` (Public), `graph.microsoft.us` (US Government L4 / GCC High) or `dod-graph.microsoft.us` (L5 / DoD).
3. **Delegated mode re-reads the host from the signed-in user** — `Get-MgContext` → environment → `Get-MgEnvironment` → `GraphEndpoint`.

A commercial tenant needs no switches; a GCC High or DoD tenant runs the same commands.

## The query

```kusto
EntraIdSignInEvents                              // Defender XDR advanced hunting table (Entra ID P2)
| where Timestamp > ago(24h)                     // time filter — the API "Timespan" also applies; the shorter wins
| where ErrorCode == 0                           // 0 = successful sign-in; anything else is a failure code
| summarize LastSignIn  = max(Timestamp),
            SignInCount = count(),
            Apps        = make_set(Application, 5)   // dynamic → arrives as a JSON array inside each row
          by AccountUpn, AccountDisplayName          // one row per user
| order by LastSignIn desc
```

`AADSignInEventsBeta` is deprecated on **19 October 2026** and replaced by `EntraIdSignInEvents`; existing queries migrate automatically.

## Script reference

### `New-HuntingAppRegistration.ps1`

| Parameter | Default | Notes |
| --- | --- | --- |
| `-DisplayName` | generated after sign-in | `Graph Security API - Hunting Demo - <alias> - <6 random characters>`. Pass an exact name to override generation; an existing exact-name match is reused (new secret added, consent verified). |
| `-TenantId` | *(current)* | Tenant ID or verified domain; also drives endpoint discovery. |
| `-Environment` | *(discovered)* | `Public` or `AzureGov` override. |
| `-SecretValidityMonths` | `12` | 1–24. Sets `passwordCredential.endDateTime`. |
| `-IncludeDelegatedScope` | off | Also adds the delegated scope, `http://localhost` public-client redirect and an `oauth2PermissionGrant` (AllPrincipals). Leave off so learners see the consent prompt with the SDK's default app. |
| `-PreviewName` | off | Signs in, prints the generated default name, and exits before any Graph or file changes. |
| `-SettingsFile` | `.\scripts\HuntingDemo.settings.json` | Identifiers and endpoints only — the secret is never written. |

Graph calls it makes (each printed as `VERB URI` while it runs): `GET /servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'` → `POST /applications` → `POST /applications/{id}/addPassword` → `POST /servicePrincipals` → `POST /servicePrincipals/{graphSpId}/appRoleAssignedTo` (= admin consent) → optional `POST /oauth2PermissionGrants`.
Sign-in scopes requested: `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All` (+ `DelegatedPermissionGrant.ReadWrite.All` with `-IncludeDelegatedScope`).

### `Invoke-HuntingQuery.ps1`

| Parameter | Default | Notes |
| --- | --- | --- |
| `-AuthMode` | `AppOnly` | `AppOnly` (client credentials via `Invoke-RestMethod`) or `Delegated` (`Connect-MgGraph`). |
| `-TenantId`, `-ClientId` | from `scripts\HuntingDemo.settings.json` | Required for AppOnly if no settings file. |
| `-ClientSecret` | `$env:HUNT_CLIENT_SECRET`, else prompt | `SecureString`. |
| `-Environment` | *(discovered)* | `Public` or `AzureGov` override. |
| `-Hours` | `24` | 1–720. Drives `ago()` in the query and the API `Timespan` (`P<days>D`). |
| `-QueryFile` | *(built-in query)* | Send a `.kql` file verbatim. |
| `-OutFile` | `.\SignIns-Last<Hours>h-<yyyyMMdd-HHmm>.json` | Full `huntingQueryResults` object. |
| `-TokenOutFile` (`-JwtOutFile`) | *(none)* | Opt-in raw JWT capture. Delegated capture requires an app created with `-IncludeDelegatedScope`. Treat the file as a bearer credential. |
| `-SettingsFile` | `.\scripts\HuntingDemo.settings.json` | Written by the setup script. |

Console output: resolved endpoints and their source, the three calls, `HTTP <status> | <n> row(s) | request-id`, the `schema` table, the first ten `results`, the saved path, and a round-trip read of the file.

## The deck

Open [`class_content/REST-APIs-JSON-Graph-Security-API.html`](class_content/REST-APIs-JSON-Graph-Security-API.html) in a browser.

| Key | Action |
| --- | --- |
| **← / →**, **Space** | Previous / next slide |
| **N** | Speaker notes (every slide has them) |
| **F** | Full screen |
| **1–9**, **Home / End** | Jump to slide / first / last |

Outline: why REST matters → REST · API · JSON → anatomy of a call → HTTP verbs → why JSON → **JSON anatomy diagram** → JSON types ↔ PowerShell → Graph Security API (endpoint, request, quotas) → `ThreatHunting.Read.All` & admin consent → token flow → the KQL → Step 1 discovery + token → Step 2 `Invoke-RestMethod` switch by switch → Step 3 response → JSON file → switch reference → prerequisites & Microsoft Learn → live demo / Q&A.

### Interactive simulations

Open any simulator from `class_content`, select **Start simulation**, then choose **Run the script** or **Run the call**. Use **Space** or **→** to advance, **←** to step back, the numbered progress segments to jump, and **Autoplay** for an unattended walkthrough. The **Slides** control returns to the deck.

Recommended sequence: app registration and admin consent → app-only client credentials → delegated sign-in and consent. Together they expose the request/response payloads, PowerShell commands, identity boundary, expected failures, and resulting tenant or file state before the live demo touches a tenant.

## The diagram

![Anatomy of a JSON Object](images/JSON-Anatomy-Diagram.png)

## Troubleshooting

| Symptom | Meaning | Fix |
| --- | --- | --- |
| `AADSTS7000215: Invalid client secret` | Wrong or expired secret | Re-run `.\scripts\New-HuntingAppRegistration.ps1` to create a fresh student-specific app and secret, then update `$env:HUNT_CLIENT_SECRET`. To add a secret to the same app instead, pass its exact name with `-DisplayName`. |
| `AADSTS700016 / AADSTS90002` | Unknown client or tenant | Check `HuntingDemo.settings.json`; pass `-TenantId` / `-ClientId` explicitly. |
| `HTTP 401` | No or invalid token | Token expired (≈1 h) or wrong cloud — check the `Endpoints :` line in the output. |
| `HTTP 403` | Token lacks `ThreatHunting.Read.All` | Admin consent not granted or not replicated yet. Portal: App registrations → API permissions → status should read *Granted for &lt;tenant&gt;*. Wait 1–2 minutes after the setup script. |
| `HTTP 429` | Throttled / CPU quota | Read the body; the script retries and honors `Retry-After`. |
| `0 row(s)` | Table empty | `EntraIdSignInEvents` needs Entra ID P2; try `-Hours 72`, or the `IdentityLogonEvents` fallback in the `.kql`. |
| "Need admin approval" (Delegated) | User cannot consent to this permission | An admin runs it once and picks *Consent on behalf of your organization*, or grants consent in the portal. |
| `Microsoft.Graph.Authentication` not found | Module missing | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` |

## Security notes

- The client secret is printed **once** by the setup script and is never written to disk by either script. Keep it in `$env:HUNT_CLIENT_SECRET` for the session or a SecretManagement vault — never in source control.
- `scripts/HuntingDemo.settings.json` contains tenant and client identifiers (not secrets) — still tenant-specific, so keep it out of the repo. The included `.gitignore` excludes it and generated query results:

  ```gitignore
  scripts/HuntingDemo.settings.json
  SignIns-*.json
  *.jwt
  ```

- For anything beyond a classroom demo prefer a certificate or a managed identity over a client secret, and scope the app to a dedicated demo tenant.
- Paste access tokens only into <https://jwt.ms> (client-side decoding) when showing the `roles` / `scp` claims. A `-TokenOutFile` file grants the token's access until expiry; never share it, and delete it immediately after the demo.

## Microsoft Learn references

- [security: runHuntingQuery](https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0) · [Microsoft Graph security API overview](https://learn.microsoft.com/graph/security-concept-overview)
- [Microsoft Graph national cloud deployments](https://learn.microsoft.com/graph/deployments) · [Microsoft Entra authentication & national clouds](https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud)
- [EntraIdSignInEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-entraidsigninevents-table) · [AADSignInEventsBeta (deprecated)](https://learn.microsoft.com/defender-xdr/advanced-hunting-aadsignineventsbeta-table) · [IdentityLogonEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identitylogonevents-table) · [Advanced hunting API quotas](https://learn.microsoft.com/defender-xdr/api-advanced-hunting)
- [Permissions and consent overview](https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview) · [Grant tenant-wide admin consent](https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent) · [Permissions reference](https://learn.microsoft.com/graph/permissions-reference)
- [Create application](https://learn.microsoft.com/graph/api/application-post-applications?view=graph-rest-1.0) · [application: addPassword](https://learn.microsoft.com/graph/api/application-addpassword?view=graph-rest-1.0) · [Grant an appRoleAssignment to a service principal](https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0) · [Create oAuth2PermissionGrant](https://learn.microsoft.com/graph/api/oauth2permissiongrant-post?view=graph-rest-1.0)
- [Microsoft Graph PowerShell authentication commands](https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands) · [Invoke-RestMethod](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod) · [ConvertTo-Json](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-json)

## Contributing

Issues and pull requests are welcome — especially additional hunting queries (drop a `.kql` in the repo and point `-QueryFile` at it), fixes for other national clouds, or translations of the deck.

## License

[Add a license — MIT is a common choice for sample code.]

---

*Sample and training material. Not an official Microsoft product; provided as-is for educational use. Author: Lorenzo Ireland, Principal Cloud Solution Architect, Microsoft Federal.*
