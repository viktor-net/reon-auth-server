#Requires -Version 7.0
<#
.SYNOPSIS
    Smoke-проверка DEV-стенда аутентификации ИС РЕОН 2.0.

.DESCRIPTION
    Всё делается через точку входа nginx (по умолчанию http://localhost:8090):
      0) стенд поднят, issuer в discovery совпадает с контрактом;
      1) client_credentials для reon-service -> HTTP 200, JWT, aud содержит reon-api;
      2) ROPC (reon-dev-smoke) для dev-branch, dev-finance, dev-admin ->
         groups, org_id (A/B), realm_access.roles, aud, TTL access-токена;
      3) SPA-клиент reon-admin-web без браузера: discovery, /auth с PKCE S256,
         параметры public-клиента через Admin API;
      4) заголовок Authorization ~9 КБ проходит через nginx (нет 400/414/431);
      5) синтетика (задача local-20261102-01): сервисные клиенты существуют,
         mdm-service получает токен по client_credentials, syn-mdm-editor и
         syn-branch-employee-1 получают ожидаемые capabilities и org_id.

    Зависимости: PowerShell 7+ (pwsh). JWT раскодируется средствами PowerShell,
    внешние утилиты не нужны.

.EXAMPLE
    pwsh -File scripts/smoke-auth.ps1

.NOTES
    Переменные окружения (или файл .env в корне репозитория):
    REON_AUTH_BASE_URL, REON_REALM, REON_SERVICE_CLIENT_SECRET,
    REON_DEV_SMOKE_CLIENT_SECRET, KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME,
    KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD (Admin API)
#>

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

# Файл .env: те же значения, что и для bash-версии smoke-проверки.
$envFile = Join-Path $repoRoot '.env'
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile -Encoding utf8) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $idx = $trimmed.IndexOf('=')
        if ($idx -lt 1) { continue }
        $name = $trimmed.Substring(0, $idx).Trim()
        $value = $trimmed.Substring($idx + 1).Trim()
        Set-Item -Path "env:$name" -Value $value
    }
}

$baseUrl = if ($env:REON_AUTH_BASE_URL) { $env:REON_AUTH_BASE_URL } else { 'http://localhost:8090' }
$realm = if ($env:REON_REALM) { $env:REON_REALM } else { 'reon' }
$serviceClientId = 'reon-service'
$serviceClientSecret = if ($env:REON_SERVICE_CLIENT_SECRET) { $env:REON_SERVICE_CLIENT_SECRET } else { 'dev-reon-service-secret-change-me' }
$smokeClientId = 'reon-dev-smoke'
$smokeClientSecret = if ($env:REON_DEV_SMOKE_CLIENT_SECRET) { $env:REON_DEV_SMOKE_CLIENT_SECRET } else { 'dev-reon-dev-smoke-secret-change-me' }

# Фиксированные UUID org_id из docker/keycloak/realm.yml
$orgIdA = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d'   # /reon/hq, /reon/hq/finance, /reon/admins
$orgIdB = '1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e'   # /reon/branch-1

# Контракт: access-токен живёт 15 минут (900 секунд).
$accessTokenTtl = 900

$script:pass = 0
$script:fail = 0

$tokenUrl = "$baseUrl/realms/$realm/protocol/openid-connect/token"
$discoveryUrl = "$baseUrl/realms/$realm/.well-known/openid-configuration"
$userinfoUrl = "$baseUrl/realms/$realm/protocol/openid-connect/userinfo"

function Write-Ok {
    param([string]$Message)
    $script:pass++
    Write-Host "  [OK]   $Message"
}

function Write-Fail {
    param([string]$Message)
    $script:fail++
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Invoke-TokenRequest {
    param([hashtable]$Body)
    $resp = Invoke-WebRequest -Uri $tokenUrl -Method Post -Body $Body `
        -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck
    [pscustomobject]@{
        Status  = [int]$resp.StatusCode
        Content = $resp.Content
    }
}

function ConvertFrom-JwtPayload {
    param([string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { throw 'JWT не содержит payload' }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
}

function Show-Claims {
    param([string]$Title, [string]$PayloadJson)
    Write-Host "--- claims access-токена $Title ---"
    $obj = $PayloadJson | ConvertFrom-Json
    Write-Host ($obj | ConvertTo-Json -Depth 10)
    Write-Host '---'
}

function Test-TokenTtl {
    param([string]$Title, $Claims)
    if ($null -eq $Claims.exp -or $null -eq $Claims.iat) {
        Write-Fail "$Title (в токене нет exp/iat)"
        return
    }
    $ttl = [int]$Claims.exp - [int]$Claims.iat
    if ($ttl -eq $accessTokenTtl) {
        Write-Ok "$Title (exp - iat = $ttl)"
    } else {
        Write-Fail "$Title (exp - iat = $ttl, ожидалось $accessTokenTtl)"
    }
}

Write-Host '=== Smoke: DEV-стенд аутентификации ИС РЕОН 2.0 ==='
Write-Host "Точка входа: $baseUrl"
Write-Host "Realm:       $realm"
Write-Host ''

# ---------------------------------------------------------------------------
# 0. Стенд поднят, issuer соответствует контракту
# ---------------------------------------------------------------------------
Write-Host '== 0. Доступность стенда и issuer'
$discovery = $null
for ($i = 1; $i -le 60; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri $discoveryUrl -SkipHttpErrorCheck
        if ([int]$resp.StatusCode -eq 200) {
            $discovery = $resp.Content
            break
        }
    } catch {
        # стенд ещё поднимается
    }
    Start-Sleep -Seconds 2
}

if ($null -eq $discovery) {
    Write-Fail "discovery недоступен через nginx ($discoveryUrl). Стенд поднят? docker compose up -d"
    Write-Host ''
    Write-Host "=== Итог: PASS=$($script:pass) FAIL=$($script:fail) ==="
    exit 1
}

Write-Ok "discovery доступен через nginx: GET /realms/$realm/.well-known/openid-configuration -> 200"
$discoveryObj = $discovery | ConvertFrom-Json
$expectedIssuer = "$baseUrl/realms/$realm"
if ($discoveryObj.issuer -eq $expectedIssuer) {
    Write-Ok "issuer в discovery = $expectedIssuer"
} else {
    Write-Fail "issuer в discovery = $($discoveryObj.issuer), ожидалось $expectedIssuer"
}

# ---------------------------------------------------------------------------
# 1. client_credentials для reon-service
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "== 1. client_credentials: $serviceClientId"
$serviceResponse = Invoke-TokenRequest -Body @{
    grant_type    = 'client_credentials'
    client_id     = $serviceClientId
    client_secret = $serviceClientSecret
}

if ($serviceResponse.Status -eq 200) {
    Write-Ok 'token-эндпоинт вернул 200'
} else {
    Write-Fail "token-эндпоинт вернул HTTP $($serviceResponse.Status)"
    Write-Host "Ответ: $($serviceResponse.Content)"
}

$servicePayloadJson = $null
if ($serviceResponse.Status -eq 200) {
    $serviceToken = ($serviceResponse.Content | ConvertFrom-Json).access_token
    if ($serviceToken) {
        Write-Ok 'получен access_token (JWT)'
        $servicePayloadJson = ConvertFrom-JwtPayload -Token $serviceToken
        Show-Claims -Title $serviceClientId -PayloadJson $servicePayloadJson
        $serviceClaims = $servicePayloadJson | ConvertFrom-Json

        if ($serviceClaims.aud -contains 'reon-api') { Write-Ok 'aud содержит reon-api' }
        else { Write-Fail "aud не содержит reon-api (aud=$($serviceClaims.aud -join ','))" }

        if ($serviceClaims.azp -eq $serviceClientId) { Write-Ok "azp = $serviceClientId" }
        else { Write-Fail "azp = $($serviceClaims.azp), ожидалось $serviceClientId" }

        if ($serviceClaims.preferred_username -eq "service-account-$serviceClientId") {
            Write-Ok "preferred_username = service-account-$serviceClientId"
        } else {
            Write-Fail "preferred_username = $($serviceClaims.preferred_username)"
        }

        Test-TokenTtl -Title "TTL access-токена $serviceClientId = $accessTokenTtl c" -Claims $serviceClaims

        # realm_access у service account не проверяется: ролей у сервисного
        # аккаунта нет по дизайну (роли живут на группах пользователей).
    } else {
        Write-Fail 'access_token не получен'
    }
}

# ---------------------------------------------------------------------------
# 2. ROPC (только DEV-клиент reon-dev-smoke) для dev-пользователей
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "== 2. ROPC через ${smokeClientId}: dev-branch, dev-finance, dev-admin"

function Test-DevUser {
    param(
        [string]$UserName,
        [string]$Password,
        [string]$ExpectedGroup,
        [string]$ExpectedOrgId
    )

    Write-Host ''
    Write-Host "-- пользователь $UserName --"
    $resp = Invoke-TokenRequest -Body @{
        grant_type    = 'password'
        client_id     = $smokeClientId
        client_secret = $smokeClientSecret
        username      = $UserName
        password      = $Password
        scope         = 'openid'
    }

    if ($resp.Status -ne 200) {
        Write-Fail "ROPC вернул HTTP $($resp.Status)"
        Write-Host "Ответ: $($resp.Content)"
        return
    }
    Write-Ok 'ROPC вернул 200'

    $token = ($resp.Content | ConvertFrom-Json).access_token
    if (-not $token) {
        Write-Fail 'access_token не получен'
        return
    }
    Write-Ok 'получен access_token (JWT)'

    $payloadJson = ConvertFrom-JwtPayload -Token $token
    Show-Claims -Title $UserName -PayloadJson $payloadJson
    $claims = $payloadJson | ConvertFrom-Json

    if ($claims.groups -contains $ExpectedGroup) { Write-Ok "groups содержит $ExpectedGroup" }
    else { Write-Fail "groups не содержит $ExpectedGroup (groups=$($claims.groups -join ','))" }

    if ($claims.org_id -eq $ExpectedOrgId) { Write-Ok "org_id = $ExpectedOrgId" }
    else { Write-Fail "org_id = $($claims.org_id), ожидалось $ExpectedOrgId" }

    if ($claims.aud -contains 'reon-api') { Write-Ok 'aud содержит reon-api' }
    else { Write-Fail "aud не содержит reon-api (aud=$($claims.aud -join ','))" }

    if ($null -ne $claims.realm_access.roles) { Write-Ok 'realm_access.roles присутствует' }
    else { Write-Fail 'realm_access.roles отсутствует' }

    if ($claims.preferred_username -eq $UserName) { Write-Ok "preferred_username = $UserName" }
    else { Write-Fail "preferred_username = $($claims.preferred_username), ожидалось $UserName" }

    Test-TokenTtl -Title "TTL access-токена $UserName = $accessTokenTtl c" -Claims $claims

    return $claims
}

$devBranchClaims = Test-DevUser -UserName 'dev-branch' -Password 'dev-branch-pass' -ExpectedGroup '/reon/branch-1' -ExpectedOrgId $orgIdB
$devFinanceClaims = Test-DevUser -UserName 'dev-finance' -Password 'dev-finance-pass' -ExpectedGroup '/reon/hq/finance' -ExpectedOrgId $orgIdA
$devAdminClaims = Test-DevUser -UserName 'dev-admin' -Password 'dev-admin-pass' -ExpectedGroup '/reon/hq' -ExpectedOrgId $orgIdA

Write-Host ''
Write-Host '-- роли через группы --'
# MASTER_ADMIN висит на /reon/admins (не на /reon/hq), поэтому дочерние группы
# /reon/hq её больше не наследуют.
if ($devAdminClaims -and ($devAdminClaims.groups -contains '/reon/hq')) {
    Write-Ok 'dev-admin: groups содержит /reon/hq'
} else {
    Write-Fail 'dev-admin: groups не содержит /reon/hq'
}

if ($devAdminClaims -and ($devAdminClaims.groups -contains '/reon/admins')) {
    Write-Ok 'dev-admin: groups содержит /reon/admins'
} else {
    Write-Fail 'dev-admin: groups не содержит /reon/admins'
}

if ($devAdminClaims -and ($devAdminClaims.realm_access.roles -contains 'MASTER_ADMIN')) {
    Write-Ok 'dev-admin: realm_access.roles содержит MASTER_ADMIN'
} else {
    Write-Fail 'dev-admin: realm_access.roles не содержит MASTER_ADMIN'
}

if ($devBranchClaims -and ($devBranchClaims.realm_access.roles -contains 'report:read')) {
    Write-Ok 'dev-branch: realm_access.roles содержит report:read'
} else {
    Write-Fail 'dev-branch: realm_access.roles не содержит report:read'
}

if ($devBranchClaims -and ($devBranchClaims.realm_access.roles -contains 'MASTER_ADMIN')) {
    Write-Fail 'dev-branch: неожиданно выдана MASTER_ADMIN'
} else {
    Write-Ok 'dev-branch: MASTER_ADMIN не выдан (/reon/branch-1 вне /reon/admins)'
}

if ($devFinanceClaims -and ($devFinanceClaims.realm_access.roles -contains 'MASTER_ADMIN')) {
    Write-Fail 'dev-finance: неожиданно выдана MASTER_ADMIN'
} else {
    Write-Ok 'dev-finance: MASTER_ADMIN не выдан (/reon/hq/finance вне /reon/admins)'
}

# ---------------------------------------------------------------------------
# 3. SPA-клиент reon-admin-web: authorization code + PKCE S256, без браузера
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== 3. SPA-клиент reon-admin-web (Code + PKCE S256)'

$spaClientId = 'reon-admin-web'
# code_challenge = base64url(sha256("test-verifier")): фиксированный вектор.
$pkceChallenge = 'JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0'
$authUrl = "$baseUrl/realms/$realm/protocol/openid-connect/auth"
$adminTokenUrl = "$baseUrl/realms/master/protocol/openid-connect/token"
$adminClientsUrl = "$baseUrl/admin/realms/$realm/clients?clientId=$spaClientId"
$adminUser = if ($env:KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME) { $env:KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME } else { 'admin' }
$adminPassword = if ($env:KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD) { $env:KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD } else { 'dev-admin-change-me' }

# a) discovery через nginx и issuer из контракта
try {
    $spaDiscovery = Invoke-WebRequest -Uri $discoveryUrl -SkipHttpErrorCheck
    $spaDiscoveryStatus = [int]$spaDiscovery.StatusCode
} catch {
    $spaDiscoveryStatus = 0
}
if ($spaDiscoveryStatus -eq 200) {
    Write-Ok 'SPA: discovery через nginx -> 200'
} else {
    Write-Fail "SPA: discovery через nginx вернул HTTP $spaDiscoveryStatus"
}
if ($spaDiscoveryStatus -eq 200 -and $discoveryObj.issuer -eq $expectedIssuer) {
    Write-Ok "SPA: issuer в discovery = $expectedIssuer"
} else {
    Write-Fail "SPA: issuer в discovery не совпадает с $expectedIssuer"
}

# b) authorization-эндпоинт не отвергает public-клиент с PKCE S256
$authQuery = 'client_id={0}&response_type=code&redirect_uri={1}&scope=openid&code_challenge={2}&code_challenge_method=S256' -f `
    $spaClientId, [uri]::EscapeDataString('http://localhost:4200/'), $pkceChallenge
$authStatus = 0
$authText = ''
try {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $httpClient = [System.Net.Http.HttpClient]::new($handler)
    $authResp = $httpClient.GetAsync("$authUrl`?$authQuery").GetAwaiter().GetResult()
    $authStatus = [int]$authResp.StatusCode
    $authText = ($authResp.Headers.ToString()) + ($authResp.Content.ReadAsStringAsync().GetAwaiter().GetResult())
    $httpClient.Dispose()
} catch {
    $authStatus = 0
    $authText = $_.Exception.Message
}

if ($authStatus -in 200, 302) {
    Write-Ok "SPA: /auth с response_type=code и PKCE S256 вернул HTTP $authStatus (форма входа или редирект)"
} else {
    Write-Fail "SPA: /auth вернул HTTP $authStatus (ожидалось 200 или 302)"
}

if ($authText -match 'invalid_client') {
    Write-Fail 'SPA: ответ /auth содержит invalid_client'
} else {
    Write-Ok 'SPA: ответ /auth не содержит invalid_client'
}

if ($authText -match 'unauthorized_client') {
    Write-Fail 'SPA: ответ /auth содержит unauthorized_client'
} else {
    Write-Ok 'SPA: ответ /auth не содержит unauthorized_client'
}

# c) Admin API: параметры клиента соответствуют контракту
$adminToken = $null
$adminStatus = 0
try {
    $adminResp = Invoke-WebRequest -Uri $adminTokenUrl -Method Post -SkipHttpErrorCheck -ContentType 'application/x-www-form-urlencoded' -Body @{
        grant_type = 'password'
        client_id  = 'admin-cli'
        username   = $adminUser
        password   = $adminPassword
    }
    $adminStatus = [int]$adminResp.StatusCode
    if ($adminStatus -eq 200) { $adminToken = ($adminResp.Content | ConvertFrom-Json).access_token }
} catch {
    $adminStatus = 0
}

if ($adminToken) {
    Write-Ok 'SPA: Admin API, токен администратора получен (admin-cli, master realm)'
    $clientsStatus = 0
    $spaClientJson = ''
    try {
        $clientsResp = Invoke-WebRequest -Uri $adminClientsUrl -Headers @{ Authorization = "Bearer $adminToken" } -SkipHttpErrorCheck
        $clientsStatus = [int]$clientsResp.StatusCode
        $spaClientJson = $clientsResp.Content
    } catch {
        $clientsStatus = 0
    }

    if ($clientsStatus -eq 200 -and $spaClientJson -match ('"clientId"\s*:\s*"' + [regex]::Escape($spaClientId) + '"')) {
        Write-Ok "SPA: Admin API, клиент $spaClientId найден"

        if ($spaClientJson -match '"publicClient"\s*:\s*true') { Write-Ok 'SPA: publicClient = true' }
        else { Write-Fail 'SPA: publicClient не true' }

        if ($spaClientJson -match '"pkce\.code\.challenge\.method"\s*:\s*"S256"') { Write-Ok 'SPA: PKCE обязателен, метод S256' }
        else { Write-Fail 'SPA: pkce.code.challenge.method не S256' }

        if ($spaClientJson -match '"http://localhost:4200/\*"') { Write-Ok 'SPA: redirectUris содержит http://localhost:4200/*' }
        else { Write-Fail 'SPA: redirectUris не содержит http://localhost:4200/*' }

        if ($spaClientJson -match '"http://localhost:4201/\*"') { Write-Ok 'SPA: redirectUris содержит http://localhost:4201/*' }
        else { Write-Fail 'SPA: redirectUris не содержит http://localhost:4201/*' }

        if ($spaClientJson -match '"http://localhost:4200"') { Write-Ok 'SPA: webOrigins содержит http://localhost:4200' }
        else { Write-Fail 'SPA: webOrigins не содержит http://localhost:4200' }

        if ($spaClientJson -match '"http://localhost:4201"') { Write-Ok 'SPA: webOrigins содержит http://localhost:4201' }
        else { Write-Fail 'SPA: webOrigins не содержит http://localhost:4201' }
    } else {
        Write-Fail "SPA: Admin API не вернул клиента $spaClientId (HTTP $clientsStatus)"
        Write-Host "Ответ: $spaClientJson"
    }
} else {
    Write-Fail "SPA: Admin API, токен администратора не получен (HTTP $adminStatus)"
}

# ---------------------------------------------------------------------------
# 4. Крупный заголовок Authorization (~9 КБ) через nginx
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== 4. Крупный заголовок Authorization (~9 КБ) через nginx'
$longToken = 'A' * 9000
try {
    $longResp = Invoke-WebRequest -Uri $userinfoUrl -Headers @{ Authorization = "Bearer $longToken" } -SkipHttpErrorCheck
    $longStatus = [int]$longResp.StatusCode
    $longBody = $longResp.Content
} catch {
    $longStatus = 0
    $longBody = $_.Exception.Message
}

Write-Host "HTTP-код на userinfo с заголовком 9 КБ: $longStatus"
switch ($longStatus) {
    { $_ -in 400, 413, 414, 431 } {
        Write-Fail "nginx отклонил крупный заголовок (HTTP $longStatus): проверьте large_client_header_buffers в docker/nginx/nginx.conf"
    }
    0 {
        Write-Fail 'запрос не выполнен (стенд недоступен)'
    }
    default {
        Write-Ok "nginx пропустил заголовок 9 КБ, ответил Keycloak (HTTP $longStatus)"
    }
}
if ($longBody) { Write-Host "Ответ Keycloak: $longBody" }

# ---------------------------------------------------------------------------
# 5. Синтетические клиенты и пользователи (задача local-20261102-01)
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== 5. Синтетические клиенты и пользователи'

# Клиенты синтетики и секрет сервисного клиента mdm-service (DEV-заглушка).
$synClients = @('mdm-service', 'reon-s3-server', 'reon-process-backend', 'reon-admin-panel', 'reon-process-ui')
$synMdmServiceClientId = 'mdm-service'
$synMdmServiceSecret = if ($env:MDM_SERVICE_CLIENT_SECRET) { $env:MDM_SERVICE_CLIENT_SECRET } else { 'dev-mdm-service-secret-change-me' }

# a) клиенты синтетики существуют в realm (Admin API)
$synAdminToken = $null
$synAdminStatus = 0
try {
    $synAdminResp = Invoke-WebRequest -Uri $adminTokenUrl -Method Post -SkipHttpErrorCheck -ContentType 'application/x-www-form-urlencoded' -Body @{
        grant_type = 'password'
        client_id  = 'admin-cli'
        username   = $adminUser
        password   = $adminPassword
    }
    $synAdminStatus = [int]$synAdminResp.StatusCode
    if ($synAdminStatus -eq 200) { $synAdminToken = ($synAdminResp.Content | ConvertFrom-Json).access_token }
} catch {
    $synAdminStatus = 0
}

foreach ($synClientId in $synClients) {
    if (-not $synAdminToken) {
        Write-Fail "синтетика: клиент $synClientId не проверен: нет токена администратора (HTTP $synAdminStatus)"
        continue
    }
    $synClientsStatus = 0
    $synClientsJson = ''
    try {
        $synClientsResp = Invoke-WebRequest -Uri "$baseUrl/admin/realms/$realm/clients?clientId=$synClientId" `
            -Headers @{ Authorization = "Bearer $synAdminToken" } -SkipHttpErrorCheck
        $synClientsStatus = [int]$synClientsResp.StatusCode
        $synClientsJson = $synClientsResp.Content
    } catch {
        $synClientsStatus = 0
    }
    if ($synClientsStatus -eq 200 -and $synClientsJson -match ('"clientId"\s*:\s*"' + [regex]::Escape($synClientId) + '"')) {
        Write-Ok "синтетика: Admin API, клиент $synClientId найден"
    } else {
        Write-Fail "синтетика: Admin API не вернул клиента $synClientId (HTTP $synClientsStatus)"
    }
}

# b) mdm-service: client_credentials
Write-Host ''
Write-Host "-- сервисный клиент $synMdmServiceClientId --"
$synMdmResponse = Invoke-TokenRequest -Body @{
    grant_type    = 'client_credentials'
    client_id     = $synMdmServiceClientId
    client_secret = $synMdmServiceSecret
}
$synMdmToken = $null
if ($synMdmResponse.Status -eq 200) {
    $synMdmToken = ($synMdmResponse.Content | ConvertFrom-Json).access_token
}

if ($synMdmToken) {
    Write-Ok "синтетика: $synMdmServiceClientId вернул токен по client_credentials (HTTP 200)"
    $synMdmPayloadJson = ConvertFrom-JwtPayload -Token $synMdmToken
    Show-Claims -Title $synMdmServiceClientId -PayloadJson $synMdmPayloadJson
    $synMdmClaims = $synMdmPayloadJson | ConvertFrom-Json
    if ($synMdmClaims.azp -eq $synMdmServiceClientId) {
        Write-Ok "синтетика: $synMdmServiceClientId azp = $synMdmServiceClientId"
    } else {
        Write-Fail "синтетика: $synMdmServiceClientId azp = $($synMdmClaims.azp), ожидалось $synMdmServiceClientId"
    }
    if ($synMdmClaims.aud -contains 'reon-api') {
        Write-Ok "синтетика: $synMdmServiceClientId aud содержит reon-api"
    } else {
        Write-Fail "синтетика: $synMdmServiceClientId aud не содержит reon-api (aud=$($synMdmClaims.aud -join ','))"
    }
} else {
    Write-Fail "синтетика: $synMdmServiceClientId client_credentials вернул HTTP $($synMdmResponse.Status)"
    Write-Fail "синтетика: $synMdmServiceClientId azp не проверен (нет токена)"
    Write-Fail "синтетика: $synMdmServiceClientId aud не проверен (нет токена)"
}

# c) syn-mdm-editor: запись мастер-данных, организация A
Write-Host ''
Write-Host '-- синтетический пользователь syn-mdm-editor --'
$synMdmEditorResponse = Invoke-TokenRequest -Body @{
    grant_type    = 'password'
    client_id     = $smokeClientId
    client_secret = $smokeClientSecret
    username      = 'syn-mdm-editor'
    password      = 'syn-mdm-editor-pass'
    scope         = 'openid'
}
$synMdmEditorToken = $null
if ($synMdmEditorResponse.Status -eq 200) {
    $synMdmEditorToken = ($synMdmEditorResponse.Content | ConvertFrom-Json).access_token
}

if ($synMdmEditorToken) {
    Write-Ok 'синтетика: syn-mdm-editor вернул токен (ROPC, HTTP 200)'
    $synMdmEditorPayloadJson = ConvertFrom-JwtPayload -Token $synMdmEditorToken
    Show-Claims -Title 'syn-mdm-editor' -PayloadJson $synMdmEditorPayloadJson
    $synMdmEditorClaims = $synMdmEditorPayloadJson | ConvertFrom-Json
    $synMdmEditorRoles = @($synMdmEditorClaims.realm_access.roles)
    if ($synMdmEditorRoles -contains 'mdm:read') {
        Write-Ok 'синтетика: syn-mdm-editor realm_access.roles содержит mdm:read'
    } else {
        Write-Fail 'синтетика: syn-mdm-editor realm_access.roles не содержит mdm:read'
    }
    if ($synMdmEditorRoles -contains 'mdm:write') {
        Write-Ok 'синтетика: syn-mdm-editor realm_access.roles содержит mdm:write'
    } else {
        Write-Fail 'синтетика: syn-mdm-editor realm_access.roles не содержит mdm:write'
    }
    if ($synMdmEditorClaims.org_id -eq $orgIdA) {
        Write-Ok "синтетика: syn-mdm-editor org_id = $orgIdA"
    } else {
        Write-Fail "синтетика: syn-mdm-editor org_id = $($synMdmEditorClaims.org_id), ожидалось $orgIdA"
    }
    if ($synMdmEditorClaims.groups -contains '/reon/hq') {
        Write-Ok 'синтетика: syn-mdm-editor groups содержит /reon/hq'
    } else {
        Write-Fail 'синтетика: syn-mdm-editor groups не содержит /reon/hq'
    }
} else {
    Write-Fail "синтетика: syn-mdm-editor ROPC вернул HTTP $($synMdmEditorResponse.Status)"
    Write-Fail 'синтетика: syn-mdm-editor realm_access.roles содержит mdm:read (нет токена)'
    Write-Fail 'синтетика: syn-mdm-editor realm_access.roles содержит mdm:write (нет токена)'
    Write-Fail 'синтетика: syn-mdm-editor org_id не проверен (нет токена)'
    Write-Fail 'синтетика: syn-mdm-editor groups не проверен (нет токена)'
}

# d) syn-branch-employee-1: только чтение, организация B
Write-Host ''
Write-Host '-- синтетический пользователь syn-branch-employee-1 --'
$synBranchResponse = Invoke-TokenRequest -Body @{
    grant_type    = 'password'
    client_id     = $smokeClientId
    client_secret = $smokeClientSecret
    username      = 'syn-branch-employee-1'
    password      = 'syn-branch-employee-1-pass'
    scope         = 'openid'
}
$synBranchToken = $null
if ($synBranchResponse.Status -eq 200) {
    $synBranchToken = ($synBranchResponse.Content | ConvertFrom-Json).access_token
}

if ($synBranchToken) {
    Write-Ok 'синтетика: syn-branch-employee-1 вернул токен (ROPC, HTTP 200)'
    $synBranchPayloadJson = ConvertFrom-JwtPayload -Token $synBranchToken
    Show-Claims -Title 'syn-branch-employee-1' -PayloadJson $synBranchPayloadJson
    $synBranchClaims = $synBranchPayloadJson | ConvertFrom-Json
    $synBranchRoles = @($synBranchClaims.realm_access.roles)
    if ($synBranchRoles -notcontains 'mdm:write') {
        Write-Ok 'синтетика: syn-branch-employee-1 realm_access.roles НЕ содержит mdm:write'
    } else {
        Write-Fail 'синтетика: syn-branch-employee-1 realm_access.roles содержит mdm:write'
    }
    if ($synBranchClaims.org_id -eq $orgIdB) {
        Write-Ok "синтетика: syn-branch-employee-1 org_id = $orgIdB"
    } else {
        Write-Fail "синтетика: syn-branch-employee-1 org_id = $($synBranchClaims.org_id), ожидалось $orgIdB"
    }
} else {
    Write-Fail "синтетика: syn-branch-employee-1 ROPC вернул HTTP $($synBranchResponse.Status)"
    Write-Fail 'синтетика: syn-branch-employee-1 realm_access.roles НЕ содержит mdm:write (нет токена)'
    Write-Fail 'синтетика: syn-branch-employee-1 org_id не проверен (нет токена)'
}

# ---------------------------------------------------------------------------
# Итог
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "=== Итог: PASS=$($script:pass) FAIL=$($script:fail) ==="
if ($script:fail -ne 0) {
    Write-Host 'Smoke-проверка НЕ пройдена.'
    exit 1
}
Write-Host 'Smoke-проверка пройдена.'
exit 0
