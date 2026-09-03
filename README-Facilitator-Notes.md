# REST APIs, JSON & the Microsoft Graph Security API — facilitator notes

**Presenter:** Lorenzo Ireland · Principal Cloud Solution Architect · Microsoft Federal
**Audience:** Microsoft Cloud Solution Architects · **Format:** 20-slide HTML deck + live PowerShell 7 demo (AppOnly, then Delegated)

## What is in this package

| File | Purpose |
| --- | --- |
| `REST-APIs-JSON-Graph-Security-API.html` | The 20-slide deck. Open in any browser (Edge recommended). Self-contained — no network needed to present. |
| `images/JSON-Anatomy-Diagram.svg` / `.png` | Stand-alone "Anatomy of a JSON Object" diagram (object, key/value pairs, six data types, array of objects, object within an object, PowerShell 7 type mapping). Same diagram is embedded on slide 8. |
| `scripts/New-HuntingAppRegistration.ps1` | **Run once, the day before.** Creates the app registration programmatically through Graph REST calls: app + `ThreatHunting.Read.All` (Application) + tenant-wide admin consent (`appRoleAssignedTo`) + a **12-month client secret** (shown once). Writes `scripts/HuntingDemo.settings.json` (identifiers and endpoints — never the secret). Optional `-IncludeDelegatedScope`. |
| `scripts/Invoke-HuntingQuery.ps1` | The live-demo script. `-AuthMode AppOnly` (raw `Invoke-RestMethod`: discovery → token → Graph) or `-AuthMode Delegated` (`Connect-MgGraph` → `Invoke-MgGraphRequest`). Reads tenant / client ID / environment from `scripts/HuntingDemo.settings.json`. |
| `SignIns-Last24h.kql` | The hunting query: every user who signed in successfully in the last 24 hours, one row per account. Runs unchanged in Defender > Advanced hunting. |

### Presenting the deck

- **← / →** or **Space** — next / previous · **N** — speaker notes (every slide has them) · **F** — full screen · **1–9** — jump to a slide · **Home / End** — first / last · click the progress bar to jump.
- Slide 20 is an animated mock terminal that "runs" the script — your cue to switch to the real `pwsh` window.

## How the endpoints are resolved (Public vs Azure Government)

Nothing is hard-coded to a cloud. Both scripts use the same `Resolve-DemoEndpoints` logic:

1. **`-Environment Public | AzureGov`** when you pass it — URLs are pulled from the Graph PowerShell environment table (`Get-MgEnvironment`: `Global` / `USGov`) when the SDK is installed, otherwise from a two-row built-in map.
2. **Otherwise, discovery from the tenant itself** — `GET https://login.microsoftonline.{com|us}/{tenant}/v2.0/.well-known/openid-configuration` (anonymous, JSON). The document's `token_endpoint` is where the token POST goes and `msgraph_host` is the Graph host: `graph.microsoft.com` (Public), `graph.microsoft.us` (GCC High) or `dod-graph.microsoft.us` (DoD). This is REST call #0 on slide 15 and a nice first GET for the class.
3. **Delegated mode re-reads the host from the signed-in user**: `Get-MgContext` → environment → `Get-MgEnvironment` → `GraphEndpoint`.

Your commercial tenant therefore just works with no switches; a GCC High or DoD tenant works with the same commands (or with `-Environment AzureGov` as an explicit override).

## Deck outline (20 slides)

| # | Slide | Layout |
| --- | --- | --- |
| 1 | Title | hero |
| 2 | Agenda | agenda |
| 3 | REST APIs: the bedrock of the modern era (Cloud · GenAI · Web apps · MCP · SecOps · Automation) | numbered list |
| 4 | What the letters stand for — REST · API · JSON | big figures |
| 5 | Anatomy of a REST call — request vs. response | split panes |
| 6 | Five HTTP verbs, with Graph examples | table |
| 7 | JSON: to, through and from every REST API · JSON in PowerShell 7 | split panes |
| 8 | **Anatomy of a JSON object** (diagram) | diagram |
| 9 | Six JSON types → PowerShell 7 | table |
| 10 | Section divider — Microsoft Graph Security API | divider |
| 11 | Advanced hunting through Microsoft Graph — endpoint · request · response & quotas | 3 columns |
| 12 | `ThreatHunting.Read.All` & admin consent — purpose, who, how (incl. programmatic), result | split panes |
| 13 | How the OAuth 2.0 token flows (registration script → discovery → token → Graph) | timeline |
| 14 | The hunting query (KQL) | code |
| 15 | Step 1 — discovery GET + token POST (`Invoke-RestMethod`) | code |
| 16 | Step 2 — `Invoke-RestMethod`, switch by switch (splatting) | code |
| 17 | Step 3 — read the response, write the JSON file | code |
| 18 | `Invoke-RestMethod` switches that matter | table |
| 19 | Prerequisites & Microsoft Learn links | split panes |
| 20 | Live demo → Q&A | terminal |

## Day-before setup

1. **Licensing / data** — Defender XDR with **Microsoft Entra ID P2** so `EntraIdSignInEvents` is populated. Paste `SignIns-Last24h.kql` into Defender > Advanced hunting once to confirm rows come back. No P2? Use the `IdentityLogonEvents` fallback at the end of the .kql (needs Defender for Identity / Defender for Cloud Apps).
2. **PowerShell 7** — `pwsh`, `$PSVersionTable.PSVersion` ≥ 7.0. Windows PowerShell 5.1 lacks `-Authentication`, `-Token`, `-StatusCodeVariable`, `-SkipHttpErrorCheck` and `ConvertFrom-SecureString -AsPlainText`.
3. **Graph PowerShell SDK** (needed by the registration script and by Delegated mode):
   `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
4. **Create the app registration** — sign in as a **Privileged Role Administrator** (or Global Administrator). Cloud Application Administrator can create the app but cannot consent to Microsoft Graph *application* permissions.

   ```powershell
   .\scripts\New-HuntingAppRegistration.ps1               # add -TenantId <id-or-domain> if you have several tenants
   ```

   What you will see, step by step (each line is a Graph REST call): `GET /servicePrincipals?$filter=appId eq '00000003-…'` (finds the `ThreatHunting.Read.All` app-role id — no hard-coded GUIDs), `POST /applications`, `POST /applications/{id}/addPassword` (12 months), `POST /servicePrincipals`, `POST /servicePrincipals/{graph}/appRoleAssignedTo` (= admin consent). It then prints **Tenant ID, Client ID and the secret — copy the secret now, it cannot be retrieved later** — and writes `scripts/HuntingDemo.settings.json`.
   Store the secret outside the scripts, e.g. `$env:HUNT_CLIENT_SECRET = '<secret>'` for the demo session (the demo script picks it up; otherwise it prompts). Prefer a certificate or managed identity for anything beyond a demo.
   Portal check: Entra admin center → App registrations → *Graph Security API - Hunting Demo* → API permissions → status **Granted for &lt;tenant&gt;**.
5. **Dry run both modes** (allow 1–2 minutes after step 4 for replication):

   ```powershell
   .\scripts\Invoke-HuntingQuery.ps1                     # AppOnly — settings file supplies tenant + client ID; prompts for the secret
   .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated # interactive sign-in; first run shows the consent prompt
   ```

   Expected AppOnly output: `Endpoints : OpenID discovery: GET https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration`, `Token acquired…`, `HTTP 200 | n row(s) | request-id …`, the schema table, the first ten users, `Saved -> .\SignIns-Last24h-<timestamp>.json`.

## Live-demo runbook (slide 20)

1. **Run 1 — AppOnly.** `.\scripts\Invoke-HuntingQuery.ps1`. Narrate the three REST calls as they print: **GET** discovery (no token) → **POST** token (form body, JSON back) → **POST** `runHuntingQuery` (Bearer header, JSON body, JSON back). Show `$status`, `request-id`, the row count. Open the JSON file in VS Code and walk slide 8's anatomy: object → `schema[]` → `results[]` → `Apps[]`.
2. **Run 2 — Delegated.** `.\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated`. The browser sign-in appears, then the **consent prompt** for `ThreatHunting.Read.All`: as a non-admin it reads "Need admin approval"; as an admin you get "Consent on behalf of your organization". Same `200 OK` afterwards. That contrast — silent app identity vs. a human consenting — *is* the lesson.
3. **Optional, memorable:** paste the app-only access token into <https://jwt.ms> (nowhere else) and compare `roles: ["ThreatHunting.Read.All"]` with the delegated token's `scp`. Then remove the admin consent in the portal and run AppOnly again: the script prints the JSON error body and `HTTP 403` — 401 vs 403 vs consent in one screen.

## Microsoft Learn sources used

- security: runHuntingQuery — <https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0>
- Microsoft Graph security API overview — <https://learn.microsoft.com/graph/security-concept-overview>
- Microsoft Graph national cloud deployments (Graph / login endpoints per cloud) — <https://learn.microsoft.com/graph/deployments>
- Microsoft Entra authentication & national clouds — <https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud>
- EntraIdSignInEvents table — <https://learn.microsoft.com/defender-xdr/advanced-hunting-entraidsigninevents-table>
- AADSignInEventsBeta table (deprecated 19 Oct 2026) — <https://learn.microsoft.com/defender-xdr/advanced-hunting-aadsignineventsbeta-table>
- IdentityLogonEvents table — <https://learn.microsoft.com/defender-xdr/advanced-hunting-identitylogonevents-table>
- Defender XDR advanced hunting API (legacy; quotas, retirement notice) — <https://learn.microsoft.com/defender-xdr/api-advanced-hunting>
- Permissions and consent overview — <https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview>
- Grant tenant-wide admin consent (portal, PowerShell, Graph API) — <https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent>
- Create application — <https://learn.microsoft.com/graph/api/application-post-applications?view=graph-rest-1.0>
- application: addPassword — <https://learn.microsoft.com/graph/api/application-addpassword?view=graph-rest-1.0>
- Grant an appRoleAssignment to a service principal — <https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0>
- Create oAuth2PermissionGrant — <https://learn.microsoft.com/graph/api/oauth2permissiongrant-post?view=graph-rest-1.0>
- Microsoft Graph PowerShell authentication commands (Connect-MgGraph, Get-MgEnvironment, Invoke-MgGraphRequest) — <https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands>
- Invoke-RestMethod (PowerShell 7) — <https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod>
- ConvertTo-Json (PowerShell 7) — <https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-json>
- Microsoft Graph permissions reference (ThreatHunting.Read.All — admin consent required for delegated and application) — <https://learn.microsoft.com/graph/permissions-reference>

## Facts worth stating precisely

- `ThreatHunting.Read.All` — display name "Run hunting queries"; delegated *and* application; **admin consent required for both**; least-privileged (and only) permission for `runHuntingQuery`.
- `POST /v1.0/security/runHuntingQuery` body: `Query` (required), `Timespan` (optional ISO 8601; default 30 days; the shorter of Timespan and the query's own time filter wins), `workspaceId` (optional). Response: `huntingQueryResults` = `schema[]` + `results[]`.
- Clouds: Global, US Government L4 (GCC High, `graph.microsoft.us`) and L5 (DoD, `dod-graph.microsoft.us`) — not China (21Vianet). GCC uses the worldwide endpoints.
- Programmatic admin consent for an application permission = an `appRoleAssignment` (principal = your service principal, resource = Microsoft Graph's service principal, appRoleId = the permission). For a delegated permission it is an `oAuth2PermissionGrant` with `consentType = AllPrincipals`.
- `addPassword` returns `secretText` exactly once; default lifetime is 2 years, the script sets `endDateTime` = now + 12 months.
- Advanced hunting service quotas (Defender XDR advanced hunting API doc): 30-day lookback · up to 100,000 rows · at least 45 calls/min per tenant (varies by tenant size) · 3-minute query timeout · `429` when CPU quota is reached (read the body).
- The legacy `api.security.microsoft.com/api/advancedhunting/run` API began retiring in January 2026 — the Graph Security API is the path forward.
- `AADSignInEventsBeta` is deprecated on 19 October 2026 and replaced by `EntraIdSignInEvents`; existing queries migrate automatically.
