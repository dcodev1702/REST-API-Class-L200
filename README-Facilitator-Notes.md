# REST APIs, JSON & the Microsoft Graph Security API — facilitator notes

**Presenter:** Lorenzo J. Ireland · Cloud Solution Architect (AI+Security) · Microsoft
**Audience:** Microsoft Cloud Solution Architects · **Format:** 20-slide HTML deck + three interactive simulations + live PowerShell 7 demo (secret, certificate, then delegated)

## What is in this package

| File | Purpose |
| --- | --- |
| `class_content/REST-APIs-JSON-Graph-Security-API.html` | The 20-slide deck. Open in any browser (Edge recommended). Self-contained — no network needed to present. |
| `class_content/Sim-App-Registration-Admin-Consent.html` | 13-step walkthrough of the setup script: app registration, correlated training certificate, secret, service principal, `ThreatHunting.Read.All`, and programmatic admin consent. |
| `class_content/Sim-AppOnly-Client-Credentials.html` | 12-step walkthrough of the app-only call: discovery, client-credentials token, `runHuntingQuery`, 401/403 boundaries, and JSON output. |
| `class_content/Sim-Delegated-Sign-In-Consent.html` | 13-step walkthrough of delegated WAM sign-in: Windows account broker, admin-consent boundary, `scp`, Graph call, and JSON output. |
| `extras/Identity_101.md` | Optional identity primer: app-only scopes, secrets, certificates, managed identities, and Graph application permissions. |
| `extras/Identity_102.md` | Optional app-role-assignment deep dive: `principalId`, `resourceId`, and `appRoleId`. |
| `extras/Identity_103.md` | Optional token-audience deep dive: resource identifiers, `/.default`, service principals, and `aud`. |
| `images/JSON-Anatomy-Diagram.svg` / `.png` | Stand-alone "Anatomy of a JSON Object" diagram (object, key/value pairs, six data types, array of objects, object within an object, PowerShell 7 type mapping). Same diagram is embedded on slide 8. |
| `scripts/New-HuntingAppRegistration.ps1` | Creates the app, consent, secret, and a 12-month self-signed certificate named `<app registration name> - TRAINING`. .NET `X509Store` copies its non-exportable private key to `Cert:\CurrentUser\My`; the `TRAINING ONLY` details block lists every correlation ID. |
| `scripts/Remove-HuntingAppRegistration.ps1` | Correlated teardown. Reads `HuntingDemo.settings.json`, revokes all secrets and registered certificate keys, removes the exact local certificate and service principal, deletes the app registration, then deletes the settings file. `-WhatIf` performs only validation and `GET` calls. |
| `scripts/Invoke-HuntingQuery.ps1` | Runs `AppOnly`, `Certificate`, or `Delegated`. Before auth it clears stale demo-token variables and the clipboard; afterwards it copies the complete JWT to the clipboard and optionally a `.jwt` file. |
| `SignIns-Last24h.kql` | The hunting query: every user who signed in successfully in the last 24 hours, one row per account. Runs unchanged in Defender > Advanced hunting. |

### Presenting the deck

- **← / →** or **Space** — next / previous · **N** — speaker notes (every slide has them) · **F** — full screen · **1–9** — jump to a slide · **Home / End** — first / last · click the progress bar to jump.
- Slide 20 is an animated mock terminal that "runs" the script — your cue to switch to the real `pwsh` window.

### Presenting the simulations

- Run the simulators in their existing order, then insert live `Certificate` mode between secret app-only and delegated. This lets learners compare two app-only `roles` tokens with one delegated `scp` token.
- Select **Start simulation**, then **Run the script** or **Run the call**. Use **Space** / **→** to advance, **←** to step back, numbered progress segments to jump, and **Autoplay** when narration does not need to pause on each payload.
- Use the simulators before the live terminal when you want every learner to see the same requests, responses, permission boundaries, and failure states. Use the **Slides** control to return to the deck.

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

1. **Class pages** — open all four files in `class_content` locally. Confirm the deck advances, notes and full screen work, each simulation starts and steps in both directions, and every **Slides** control returns to the deck.
2. **Licensing / data** — Defender XDR with **Microsoft Entra ID P2** so `EntraIdSignInEvents` is populated. Paste `SignIns-Last24h.kql` into Defender > Advanced hunting once to confirm rows come back. No P2? Use the `IdentityLogonEvents` fallback at the end of the .kql (needs Defender for Identity / Defender for Cloud Apps).
3. **PowerShell 7.3+** — `pwsh`, `$PSVersionTable.PSVersion` ≥ 7.3. Certificate naming uses the .NET 7 X.500 builder; Windows PowerShell 5.1 also lacks the required REST switches.
4. **Graph PowerShell SDK** (needed by setup and token acquisition):
   `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
5. **Create the app registration** — sign in as a **Privileged Role Administrator** (or Global Administrator). Cloud Application Administrator can create the app but cannot consent to Microsoft Graph *application* permissions.

   ```powershell
   .\scripts\New-HuntingAppRegistration.ps1 -PreviewName # optional name preview; creates nothing
   .\scripts\New-HuntingAppRegistration.ps1 -IncludeDelegatedScope -CertificateValidityMonths 12
   ```

   The script creates the app, builds a 12-month RSA-4096/SHA-256 certificate named `<app registration name> - TRAINING`, copies it through `X509Store.Add()` into Current User > Personal, and `PATCH`es its public key into the app before issuing the secret. The `TRAINING ONLY CERTIFICATE DETAILS` block includes app name, client ID, object ID and tenant ID. It then creates the service principal and app-role assignment.
   Store the secret outside the scripts, e.g. `$env:HUNT_CLIENT_SECRET = '<secret>'` for the demo session (the demo script picks it up; otherwise it prompts). Prefer a certificate or managed identity for anything beyond a demo.
   Portal check: Entra admin center → App registrations → *Graph Security API - Hunting Demo - &lt;alias&gt; - &lt;6 random characters&gt;* → API permissions → status **Granted for &lt;tenant&gt;**.
6. **Dry run all three modes** (allow 1–2 minutes after step 5 for replication):

   ```powershell
   .\scripts\Invoke-HuntingQuery.ps1 -TokenOutFile .\app-only-token.jwt
   .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Certificate -TokenOutFile .\certificate-token.jwt
   .\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated -TokenOutFile .\delegated-token.jwt
   ```

   Every run clears the prior clipboard/token variables and copies the complete JWT to the clipboard for jwt.ms. File capture is optional. Delegated auth requires setup with `-IncludeDelegatedScope`.

   Expected output includes `Clipboard and transient demo-token variables reset`, `Complete JWT copied to clipboard`, `HTTP 200`, the schema/results, and the saved response path.

## Live-demo runbook (slide 20)

1. **Run 1 — AppOnly secret.** `.\scripts\Invoke-HuntingQuery.ps1`. Narrate discovery → secret token POST → hunting POST. Paste the clipboard into jwt.ms and show `roles`.
2. **Run 2 — Certificate.** `.\scripts\Invoke-HuntingQuery.ps1 -AuthMode Certificate`. Match `<app registration name> - TRAINING` in the local store to the app, then use the `TRAINING ONLY` details block/settings for client ID, object ID and tenant ID correlation. The private key signs a client assertion; Entra stores only the public key. Paste the new clipboard token into jwt.ms: `roles` is unchanged because the identity and permission are unchanged.
3. **Run 3 — Delegated.** `.\scripts\Invoke-HuntingQuery.ps1 -AuthMode Delegated`. Windows Web Account Manager presents the account selector. This public-client flow uses no certificate or client secret. Compare the resulting `scp` and user claims with both app-only tokens.
4. **Teardown.** Clear the clipboard (`Set-Clipboard -Value ''`) and remove saved `.jwt` files. Preview `.\scripts\Remove-HuntingAppRegistration.ps1 -WhatIf`; verify its app IDs and certificate thumbprint against the setup output, then run `.\scripts\Remove-HuntingAppRegistration.ps1`. The script prompts once and removes the secrets, registered certificate keys, local private-key certificate, enterprise app/consent, app registration, environment secret, and settings file.

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
- application: removePassword — <https://learn.microsoft.com/graph/api/application-removepassword?view=graph-rest-1.0>
- Update application — <https://learn.microsoft.com/graph/api/application-update?view=graph-rest-1.0>
- Delete servicePrincipal — <https://learn.microsoft.com/graph/api/serviceprincipal-delete?view=graph-rest-1.0>
- Delete application — <https://learn.microsoft.com/graph/api/application-delete?view=graph-rest-1.0>
- Add a certificate to an app using Microsoft Graph — <https://learn.microsoft.com/graph/applications-how-to-add-certificate>
- Create a self-signed certificate for app authentication — <https://learn.microsoft.com/entra/identity-platform/howto-create-self-signed-certificate>
- Grant an appRoleAssignment to a service principal — <https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0>
- Create oAuth2PermissionGrant — <https://learn.microsoft.com/graph/api/oauth2permissiongrant-post?view=graph-rest-1.0>
- Microsoft Graph PowerShell authentication commands (Connect-MgGraph, Get-MgEnvironment, Invoke-MgGraphRequest) — <https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands>
- MSAL.NET with Windows Web Account Manager — <https://learn.microsoft.com/entra/msal/dotnet/acquiring-tokens/desktop-mobile/wam>
- Invoke-RestMethod (PowerShell 7) — <https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod>
- ConvertTo-Json (PowerShell 7) — <https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-json>
- Microsoft Graph permissions reference (ThreatHunting.Read.All — admin consent required for delegated and application) — <https://learn.microsoft.com/graph/permissions-reference>

## Facts worth stating precisely

- `ThreatHunting.Read.All` — display name "Run hunting queries"; delegated *and* application; **admin consent required for both**; least-privileged (and only) permission for `runHuntingQuery`.
- `POST /v1.0/security/runHuntingQuery` body: `Query` (required), `Timespan` (optional ISO 8601; default 30 days; the shorter of Timespan and the query's own time filter wins), `workspaceId` (optional). Response: `huntingQueryResults` = `schema[]` + `results[]`.
- Clouds: Global, US Government L4 (GCC High, `graph.microsoft.us`) and L5 (DoD, `dod-graph.microsoft.us`) — not China (21Vianet). GCC uses the worldwide endpoints.
- Programmatic admin consent for an application permission = an `appRoleAssignment` (principal = your service principal, resource = Microsoft Graph's service principal, appRoleId = the permission). For a delegated permission it is an `oAuth2PermissionGrant` with `consentType = AllPrincipals`.
- `addPassword` returns `secretText` exactly once; default lifetime is 2 years, the script sets `endDateTime` = now + 12 months.
- The training certificate defaults to 12 months (`-CertificateValidityMonths` accepts 1–24), is copied to Current User > Personal with .NET `X509Store`, and is imported without the `Exportable` flag. Certificate/key file extensions are Git-ignored; setup exports no certificate files.
- Delegated mode uses WAM and the public-client broker redirect `ms-appx-web://microsoft.aad.brokerplugin/{client_id}`. It never uses the training certificate or client secret.
- Advanced hunting service quotas (Defender XDR advanced hunting API doc): 30-day lookback · up to 100,000 rows · at least 45 calls/min per tenant (varies by tenant size) · 3-minute query timeout · `429` when CPU quota is reached (read the body).
- The legacy `api.security.microsoft.com/api/advancedhunting/run` API began retiring in January 2026 — the Graph Security API is the path forward.
- `AADSignInEventsBeta` is deprecated on 19 October 2026 and replaced by `EntraIdSignInEvents`; existing queries migrate automatically.
