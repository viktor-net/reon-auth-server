#!/usr/bin/env bash
# Smoke-проверка DEV-стенда аутентификации ИС РЕОН 2.0.
#
# Всё делается через точку входа nginx (по умолчанию http://localhost:8090):
#   0) стенд поднят, issuer в discovery совпадает с контрактом;
#   1) client_credentials для reon-service -> HTTP 200, JWT, aud содержит reon-api;
#   2) ROPC (reon-dev-smoke) для dev-branch, dev-finance, dev-admin ->
#      groups, org_id (A/B), realm_access.roles, aud, TTL access-токена;
#   3) SPA-клиент reon-admin-web без браузера: discovery, /auth с PKCE S256,
#      параметры public-клиента через Admin API;
#   4) заголовок Authorization ~9 КБ проходит через nginx (нет 400/414/431);
#   5) синтетика (задача local-20261102-01): сервисные клиенты существуют,
#      mdm-service получает токен по client_credentials, syn-mdm-editor и
#      syn-branch-employee-1 получают ожидаемые capabilities и org_id.
#
# Зависимости: bash, curl, base64 (есть в Git Bash и любом Linux).
# jq или python используются только для читаемого вывода JSON; сами проверки
# claims работают и без них.
#
# Запуск:
#   bash scripts/smoke-auth.sh
#
# Переменные окружения (или файл .env в корне репозитория):
#   REON_AUTH_BASE_URL, REON_REALM, REON_SERVICE_CLIENT_SECRET,
#   REON_DEV_SMOKE_CLIENT_SECRET

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

# shellcheck disable=SC1091
if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    . "$REPO_ROOT/.env"
    set +a
fi

BASE_URL="${REON_AUTH_BASE_URL:-http://localhost:8090}"
REALM="${REON_REALM:-reon}"
SERVICE_CLIENT_ID="reon-service"
SERVICE_CLIENT_SECRET="${REON_SERVICE_CLIENT_SECRET:-dev-reon-service-secret-change-me}"
SMOKE_CLIENT_ID="reon-dev-smoke"
SMOKE_CLIENT_SECRET="${REON_DEV_SMOKE_CLIENT_SECRET:-dev-reon-dev-smoke-secret-change-me}"

# Фиксированные UUID org_id из docker/keycloak/realm.yml
ORG_ID_A="0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"   # /reon/hq, /reon/hq/finance
ORG_ID_B="1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"   # /reon/branch-1

PASS=0
FAIL=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if command -v jq >/dev/null 2>&1; then
    JSON_TOOL="jq"
elif command -v python3 >/dev/null 2>&1 && python3 -c '' >/dev/null 2>&1; then
    # python3 в Windows может быть заглушкой Microsoft Store: проверяем запуск.
    JSON_TOOL="python3"
elif command -v python >/dev/null 2>&1 && python -c '' >/dev/null 2>&1; then
    JSON_TOOL="python"
else
    JSON_TOOL="none"
fi

ok() { PASS=$((PASS + 1)); printf '  [OK]   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$*"; }

check_contains() { # $1 описание, $2 текст, $3 ожидаемая подстрока
    if printf '%s' "$2" | grep -Fq -- "$3"; then
        ok "$1"
    else
        bad "$1 (не найдено: $3)"
    fi
}

check_not_contains() { # $1 описание, $2 текст, $3 запрещённая подстрока
    if printf '%s' "$2" | grep -Fq -- "$3"; then
        bad "$1 (неожиданно найдено: $3)"
    else
        ok "$1"
    fi
}

check_regex() { # $1 описание, $2 текст, $3 регулярное выражение
    if printf '%s' "$2" | grep -Eq -- "$3"; then
        ok "$1"
    else
        bad "$1 (не найдено по шаблону: $3)"
    fi
}

check_claim_equals() { # $1 описание, $2 json, $3 claim, $4 ожидаемое значение
    if printf '%s' "$2" | grep -Eq "\"$3\"[[:space:]]*:[[:space:]]*\"$4\""; then
        ok "$1"
    else
        bad "$1 (ожидалось $3 = $4)"
    fi
}

pretty_file() { # $1 файл с JSON -> читаемый JSON в stdout
    case "$JSON_TOOL" in
        jq) jq . "$1" 2>/dev/null || cat "$1" ;;
        python3 | python)
            "$JSON_TOOL" -c 'import json,sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
print()' "$1" 2>/dev/null || cat "$1"
            ;;
        *) cat "$1" ;;
    esac
}

json_access_token() { # $1 файл с ответом token-эндпоинта
    case "$JSON_TOOL" in
        jq) jq -r '.access_token // empty' "$1" 2>/dev/null ;;
        python3 | python)
            "$JSON_TOOL" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("access_token", ""))' "$1" 2>/dev/null
            ;;
        *)
            sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1"
            ;;
    esac
}

jwt_payload() { # $1 = JWT -> payload (JSON) в stdout; base64url без внешних зависимостей
    local token="$1" payload pad
    payload="${token#*.}"
    payload="${payload%%.*}"
    payload="${payload//-/+}"
    payload="${payload//_//}"
    case $((${#payload} % 4)) in
        2) payload="${payload}==" ;;
        3) payload="${payload}=" ;;
        1) return 1 ;;
    esac
    printf '%s' "$payload" | base64 -d 2>/dev/null
}

jwt_numeric_claim() { # $1 payload (JSON), $2 имя числового claim
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" | head -n 1
}

# Контракт: access-токен живёт 15 минут (900 секунд).
ACCESS_TOKEN_TTL=900

check_token_ttl() { # $1 описание, $2 payload (JSON)
    local exp iat ttl
    exp="$(jwt_numeric_claim "$2" exp)"
    iat="$(jwt_numeric_claim "$2" iat)"
    if [ -z "$exp" ] || [ -z "$iat" ]; then
        bad "$1 (в токене нет exp/iat)"
        return
    fi
    ttl=$((exp - iat))
    if [ "$ttl" -eq "$ACCESS_TOKEN_TTL" ]; then
        ok "$1 (exp - iat = $ttl)"
    else
        bad "$1 (exp - iat = $ttl, ожидалось $ACCESS_TOKEN_TTL)"
    fi
}

post_token() { # $1 файл ответа, дальше аргументы curl
    local out="$1"
    shift
    curl -sS -o "$out" -w '%{http_code}' -X POST \
        "$BASE_URL/realms/$REALM/protocol/openid-connect/token" "$@"
}

printf '=== Smoke: DEV-стенд аутентификации ИС РЕОН 2.0 ===\n'
printf 'Точка входа: %s\n' "$BASE_URL"
printf 'Realm:       %s\n' "$REALM"
printf 'JSON-инструмент для печати: %s\n\n' "$JSON_TOOL"

# ---------------------------------------------------------------------------
# 0. Стенд поднят, issuer соответствует контракту
# ---------------------------------------------------------------------------
printf '== 0. Доступность стенда и issuer\n'
DISCOVERY_URL="$BASE_URL/realms/$REALM/.well-known/openid-configuration"
http_code="000"
for _ in $(seq 1 60); do
    http_code="$(curl -sS -o "$TMP_DIR/discovery.json" -w '%{http_code}' "$DISCOVERY_URL" 2>/dev/null || echo 000)"
    [ "$http_code" = "200" ] && break
    sleep 2
done

if [ "$http_code" = "200" ]; then
    ok "discovery доступен через nginx: GET /realms/$REALM/.well-known/openid-configuration -> 200"
    discovery="$(cat "$TMP_DIR/discovery.json")"
    check_claim_equals "issuer в discovery = $BASE_URL/realms/$REALM" "$discovery" "issuer" "$BASE_URL/realms/$REALM"
else
    bad "discovery недоступен через nginx (HTTP $http_code). Стенд поднят? docker compose up -d"
    printf '\nИтог: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. client_credentials для reon-service
# ---------------------------------------------------------------------------
printf '\n== 1. client_credentials: %s\n' "$SERVICE_CLIENT_ID"
code="$(post_token "$TMP_DIR/service.json" \
    -d grant_type=client_credentials \
    -d client_id="$SERVICE_CLIENT_ID" \
    --data-urlencode "client_secret=$SERVICE_CLIENT_SECRET")"
code="${code:-000}"

if [ "$code" = "200" ]; then
    ok "token-эндпоинт вернул 200"
else
    bad "token-эндпоинт вернул HTTP $code"
    printf 'Ответ: %s\n' "$(cat "$TMP_DIR/service.json")"
fi

service_token="$(json_access_token "$TMP_DIR/service.json")"
if [ -n "$service_token" ]; then
    ok "получен access_token (JWT)"
    jwt_payload "$service_token" >"$TMP_DIR/service.payload.json"
    service_payload="$(cat "$TMP_DIR/service.payload.json")"
    printf -- '--- claims access-токена %s ---\n' "$SERVICE_CLIENT_ID"
    pretty_file "$TMP_DIR/service.payload.json"
    printf -- '---\n'
    check_contains "aud содержит reon-api" "$service_payload" '"reon-api"'
    check_claim_equals "azp = $SERVICE_CLIENT_ID" "$service_payload" "azp" "$SERVICE_CLIENT_ID"
    check_contains "preferred_username = service-account-$SERVICE_CLIENT_ID" "$service_payload" "service-account-$SERVICE_CLIENT_ID"
    check_token_ttl "TTL access-токена $SERVICE_CLIENT_ID = $ACCESS_TOKEN_TTL c" "$service_payload"
    # realm_access.roles у service account не проверяется: ролей у сервисного
    # аккаунта нет по дизайну (роли живут на группах пользователей); проверки
    # azp и aud выше достаточны.
else
    bad "access_token не получен"
fi

# ---------------------------------------------------------------------------
# 2. ROPC (только DEV-клиент reon-dev-smoke) для dev-пользователей
# ---------------------------------------------------------------------------
printf '\n== 2. ROPC через %s: dev-branch, dev-finance, dev-admin\n' "$SMOKE_CLIENT_ID"

# $1 username, $2 пароль, $3 ожидаемая группа, $4 ожидаемый org_id
check_dev_user() {
    local username="$1" password="$2" expected_group="$3" expected_org_id="$4"
    local out="$TMP_DIR/$username.json" code token payload

    printf '\n-- пользователь %s --\n' "$username"
    code="$(post_token "$out" \
        -d grant_type=password \
        -d client_id="$SMOKE_CLIENT_ID" \
        --data-urlencode "client_secret=$SMOKE_CLIENT_SECRET" \
        -d username="$username" \
        --data-urlencode "password=$password" \
        -d scope=openid)"
    code="${code:-000}"

    if [ "$code" = "200" ]; then
        ok "ROPC вернул 200"
    else
        bad "ROPC вернул HTTP $code"
        printf 'Ответ: %s\n' "$(cat "$out")"
        return
    fi

    token="$(json_access_token "$out")"
    if [ -z "$token" ]; then
        bad "access_token не получен"
        return
    fi
    ok "получен access_token (JWT)"

    jwt_payload "$token" >"$TMP_DIR/$username.payload.json"
    payload="$(cat "$TMP_DIR/$username.payload.json")"

    printf -- '--- claims access-токена %s ---\n' "$username"
    pretty_file "$TMP_DIR/$username.payload.json"
    printf -- '---\n'

    check_contains "groups содержит $expected_group" "$payload" "\"$expected_group\""
    check_claim_equals "org_id = $expected_org_id" "$payload" "org_id" "$expected_org_id"
    check_contains "aud содержит reon-api" "$payload" '"reon-api"'
    check_contains "realm_access.roles присутствует" "$payload" '"realm_access"'
    check_claim_equals "preferred_username = $username" "$payload" "preferred_username" "$username"
    check_token_ttl "TTL access-токена $username = $ACCESS_TOKEN_TTL c" "$payload"
}

check_dev_user "dev-branch" "dev-branch-pass" "/reon/branch-1" "$ORG_ID_B"
check_dev_user "dev-finance" "dev-finance-pass" "/reon/hq/finance" "$ORG_ID_A"
check_dev_user "dev-admin" "dev-admin-pass" "/reon/hq" "$ORG_ID_A"

# Роли приходят через группы: MASTER_ADMIN висит на /reon/admins (не на /reon/hq),
# поэтому дочерние группы /reon/hq её больше не наследуют.
dev_admin_payload="$(cat "$TMP_DIR/dev-admin.payload.json" 2>/dev/null || true)"
dev_branch_payload="$(cat "$TMP_DIR/dev-branch.payload.json" 2>/dev/null || true)"
dev_finance_payload="$(cat "$TMP_DIR/dev-finance.payload.json" 2>/dev/null || true)"
printf '\n-- роли через группы --\n'
check_contains "dev-admin: groups содержит /reon/hq" "$dev_admin_payload" '"/reon/hq"'
check_contains "dev-admin: groups содержит /reon/admins" "$dev_admin_payload" '"/reon/admins"'
check_contains "dev-admin: realm_access.roles содержит MASTER_ADMIN" "$dev_admin_payload" '"MASTER_ADMIN"'
check_contains "dev-branch: realm_access.roles содержит report:read" "$dev_branch_payload" '"report:read"'
check_not_contains "dev-branch: MASTER_ADMIN не выдан (/reon/branch-1 вне /reon/admins)" "$dev_branch_payload" '"MASTER_ADMIN"'
check_not_contains "dev-finance: MASTER_ADMIN не выдан (/reon/hq/finance вне /reon/admins)" "$dev_finance_payload" '"MASTER_ADMIN"'

# ---------------------------------------------------------------------------
# 3. SPA-клиент reon-admin-web: authorization code + PKCE S256, без браузера
# ---------------------------------------------------------------------------
printf '\n== 3. SPA-клиент reon-admin-web (Code + PKCE S256)\n'

SPA_CLIENT_ID="reon-admin-web"
# code_challenge = base64url(sha256("test-verifier")): фиксированный вектор,
# чтобы проверка не зависела от наличия openssl.
PKCE_CHALLENGE="JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0"
AUTH_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/auth"
ADMIN_TOKEN_URL="$BASE_URL/realms/master/protocol/openid-connect/token"
ADMIN_CLIENTS_URL="$BASE_URL/admin/realms/$REALM/clients?clientId=$SPA_CLIENT_ID"
ADMIN_USER="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD:-dev-admin-change-me}"

# a) discovery через nginx и issuer из контракта
spa_discovery_code="$(curl -sS -o "$TMP_DIR/spa-discovery.json" -w '%{http_code}' "$DISCOVERY_URL" 2>/dev/null)"
spa_discovery_code="${spa_discovery_code:-000}"
if [ "$spa_discovery_code" = "200" ]; then
    ok "SPA: discovery через nginx -> 200"
else
    bad "SPA: discovery через nginx вернул HTTP $spa_discovery_code"
fi
check_claim_equals "SPA: issuer в discovery = $BASE_URL/realms/$REALM" \
    "$(cat "$TMP_DIR/spa-discovery.json" 2>/dev/null || true)" "issuer" "$BASE_URL/realms/$REALM"

# b) authorization-эндпоинт не отвергает public-клиент с PKCE S256
auth_code="$(curl -sS -D "$TMP_DIR/spa-auth.headers" -o "$TMP_DIR/spa-auth.body" -w '%{http_code}' \
    -G "$AUTH_URL" \
    --data-urlencode "client_id=$SPA_CLIENT_ID" \
    --data-urlencode "response_type=code" \
    --data-urlencode "redirect_uri=http://localhost:4200/" \
    --data-urlencode "scope=openid" \
    --data-urlencode "code_challenge=$PKCE_CHALLENGE" \
    --data-urlencode "code_challenge_method=S256" 2>/dev/null)"
auth_code="${auth_code:-000}"
case "$auth_code" in
    200 | 302)
        ok "SPA: /auth с response_type=code и PKCE S256 вернул HTTP $auth_code (форма входа или редирект)"
        ;;
    *)
        bad "SPA: /auth вернул HTTP $auth_code (ожидалось 200 или 302)"
        ;;
esac
auth_text="$(cat "$TMP_DIR/spa-auth.headers" 2>/dev/null || true)
$(cat "$TMP_DIR/spa-auth.body" 2>/dev/null || true)"
check_not_contains "SPA: ответ /auth не содержит invalid_client" "$auth_text" "invalid_client"
check_not_contains "SPA: ответ /auth не содержит unauthorized_client" "$auth_text" "unauthorized_client"

# c) Admin API: параметры клиента соответствуют контракту
admin_code="$(curl -sS -o "$TMP_DIR/admin-token.json" -w '%{http_code}' -X POST "$ADMIN_TOKEN_URL" \
    -d grant_type=password \
    -d client_id=admin-cli \
    --data-urlencode "username=$ADMIN_USER" \
    --data-urlencode "password=$ADMIN_PASSWORD" 2>/dev/null)"
admin_code="${admin_code:-000}"
admin_token=""
if [ "$admin_code" = "200" ]; then
    admin_token="$(json_access_token "$TMP_DIR/admin-token.json")"
fi

if [ -n "$admin_token" ]; then
    ok "SPA: Admin API, токен администратора получен (admin-cli, master realm)"
    clients_code="$(curl -sS -o "$TMP_DIR/spa-client.json" -w '%{http_code}' \
        -H "Authorization: Bearer $admin_token" "$ADMIN_CLIENTS_URL" 2>/dev/null)"
    clients_code="${clients_code:-000}"
    spa_client="$(cat "$TMP_DIR/spa-client.json" 2>/dev/null || true)"
    if [ "$clients_code" = "200" ] && printf '%s' "$spa_client" | grep -Fq "\"clientId\":\"$SPA_CLIENT_ID\""; then
        ok "SPA: Admin API, клиент $SPA_CLIENT_ID найден"
        check_regex "SPA: publicClient = true" "$spa_client" '"publicClient"[[:space:]]*:[[:space:]]*true'
        check_regex "SPA: PKCE обязателен, метод S256" "$spa_client" '"pkce\.code\.challenge\.method"[[:space:]]*:[[:space:]]*"S256"'
        check_contains "SPA: redirectUris содержит http://localhost:4200/*" "$spa_client" '"http://localhost:4200/*"'
        check_contains "SPA: redirectUris содержит http://localhost:4201/*" "$spa_client" '"http://localhost:4201/*"'
        check_contains "SPA: webOrigins содержит http://localhost:4200" "$spa_client" '"http://localhost:4200"'
        check_contains "SPA: webOrigins содержит http://localhost:4201" "$spa_client" '"http://localhost:4201"'
    else
        bad "SPA: Admin API не вернул клиента $SPA_CLIENT_ID (HTTP $clients_code)"
        printf 'Ответ: %s\n' "$spa_client"
    fi
else
    bad "SPA: Admin API, токен администратора не получен (HTTP $admin_code)"
    printf 'Ответ: %s\n' "$(cat "$TMP_DIR/admin-token.json" 2>/dev/null || true)"
fi

# ---------------------------------------------------------------------------
# 4. Крупный заголовок Authorization (~9 КБ) через nginx
# ---------------------------------------------------------------------------
printf '\n== 4. Крупный заголовок Authorization (~9 КБ) через nginx\n'
LONG_TOKEN="$(head -c 9000 /dev/zero | tr '\0' 'A')"
USERINFO_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/userinfo"
code="$(curl -sS -o "$TMP_DIR/long.json" -w '%{http_code}' \
    -H "Authorization: Bearer $LONG_TOKEN" "$USERINFO_URL" 2>/dev/null)"
code="${code:-000}"

printf 'HTTP-код на userinfo с заголовком 9 КБ: %s\n' "$code"
case "$code" in
    400 | 413 | 414 | 431)
        bad "nginx отклонил крупный заголовок (HTTP $code): проверьте large_client_header_buffers в docker/nginx/nginx.conf"
        ;;
    000)
        bad "запрос не выполнен (стенд недоступен)"
        ;;
    *)
        ok "nginx пропустил заголовок 9 КБ, ответил Keycloak (HTTP $code)"
        ;;
esac
if [ -s "$TMP_DIR/long.json" ]; then
    printf 'Ответ Keycloak: %s\n' "$(cat "$TMP_DIR/long.json")"
fi

# ---------------------------------------------------------------------------
# 5. Синтетические клиенты и пользователи (задача local-20261102-01)
# ---------------------------------------------------------------------------
printf '\n== 5. Синтетические клиенты и пользователи\n'

# Клиенты синтетики и секрет сервисного клиента mdm-service (DEV-заглушка).
SYN_CLIENTS="mdm-service reon-s3-server reon-process-backend reon-admin-panel reon-process-ui"
SYN_MDM_SERVICE_CLIENT_ID="mdm-service"
SYN_MDM_SERVICE_CLIENT_SECRET="${MDM_SERVICE_CLIENT_SECRET:-dev-mdm-service-secret-change-me}"

# a) клиенты синтетики существуют в realm (Admin API)
syn_admin_code="$(curl -sS -o "$TMP_DIR/syn-admin-token.json" -w '%{http_code}' -X POST "$ADMIN_TOKEN_URL" \
    -d grant_type=password \
    -d client_id=admin-cli \
    --data-urlencode "username=$ADMIN_USER" \
    --data-urlencode "password=$ADMIN_PASSWORD" 2>/dev/null)"
syn_admin_code="${syn_admin_code:-000}"
syn_admin_token=""
if [ "$syn_admin_code" = "200" ]; then
    syn_admin_token="$(json_access_token "$TMP_DIR/syn-admin-token.json")"
fi

for syn_client in $SYN_CLIENTS; do
    if [ -z "$syn_admin_token" ]; then
        bad "синтетика: клиент $syn_client не проверен: нет токена администратора (HTTP $syn_admin_code)"
        continue
    fi
    syn_clients_code="$(curl -sS -o "$TMP_DIR/syn-client-$syn_client.json" -w '%{http_code}' \
        -H "Authorization: Bearer $syn_admin_token" \
        "$BASE_URL/admin/realms/$REALM/clients?clientId=$syn_client" 2>/dev/null)"
    syn_clients_code="${syn_clients_code:-000}"
    if [ "$syn_clients_code" = "200" ] && grep -Fq "\"clientId\":\"$syn_client\"" "$TMP_DIR/syn-client-$syn_client.json"; then
        ok "синтетика: Admin API, клиент $syn_client найден"
    else
        bad "синтетика: Admin API не вернул клиента $syn_client (HTTP $syn_clients_code)"
    fi
done

# b) mdm-service: client_credentials
printf '\n-- сервисный клиент %s --\n' "$SYN_MDM_SERVICE_CLIENT_ID"
code="$(post_token "$TMP_DIR/syn-mdm-service.json" \
    -d grant_type=client_credentials \
    -d client_id="$SYN_MDM_SERVICE_CLIENT_ID" \
    --data-urlencode "client_secret=$SYN_MDM_SERVICE_CLIENT_SECRET")"
code="${code:-000}"
syn_mdm_service_token=""
if [ "$code" = "200" ]; then
    syn_mdm_service_token="$(json_access_token "$TMP_DIR/syn-mdm-service.json")"
fi

if [ -n "$syn_mdm_service_token" ]; then
    ok "синтетика: $SYN_MDM_SERVICE_CLIENT_ID вернул токен по client_credentials (HTTP 200)"
    jwt_payload "$syn_mdm_service_token" >"$TMP_DIR/syn-mdm-service.payload.json"
    syn_mdm_service_payload="$(cat "$TMP_DIR/syn-mdm-service.payload.json")"
    printf -- '--- claims access-токена %s ---\n' "$SYN_MDM_SERVICE_CLIENT_ID"
    pretty_file "$TMP_DIR/syn-mdm-service.payload.json"
    printf -- '---\n'
    check_claim_equals "синтетика: $SYN_MDM_SERVICE_CLIENT_ID azp = $SYN_MDM_SERVICE_CLIENT_ID" \
        "$syn_mdm_service_payload" "azp" "$SYN_MDM_SERVICE_CLIENT_ID"
    check_contains "синтетика: $SYN_MDM_SERVICE_CLIENT_ID aud содержит reon-api" \
        "$syn_mdm_service_payload" '"reon-api"'
else
    bad "синтетика: $SYN_MDM_SERVICE_CLIENT_ID client_credentials вернул HTTP $code"
    bad "синтетика: $SYN_MDM_SERVICE_CLIENT_ID azp не проверен (нет токена)"
    bad "синтетика: $SYN_MDM_SERVICE_CLIENT_ID aud не проверен (нет токена)"
fi

# c) syn-mdm-editor: запись мастер-данных, организация A
printf '\n-- синтетический пользователь syn-mdm-editor --\n'
code="$(post_token "$TMP_DIR/syn-mdm-editor.json" \
    -d grant_type=password \
    -d client_id="$SMOKE_CLIENT_ID" \
    --data-urlencode "client_secret=$SMOKE_CLIENT_SECRET" \
    -d username=syn-mdm-editor \
    --data-urlencode "password=syn-mdm-editor-pass" \
    -d scope=openid)"
code="${code:-000}"
syn_mdm_editor_token=""
if [ "$code" = "200" ]; then
    syn_mdm_editor_token="$(json_access_token "$TMP_DIR/syn-mdm-editor.json")"
fi

if [ -n "$syn_mdm_editor_token" ]; then
    ok "синтетика: syn-mdm-editor вернул токен (ROPC, HTTP 200)"
    jwt_payload "$syn_mdm_editor_token" >"$TMP_DIR/syn-mdm-editor.payload.json"
    syn_mdm_editor_payload="$(cat "$TMP_DIR/syn-mdm-editor.payload.json")"
    printf -- '--- claims access-токена syn-mdm-editor ---\n'
    pretty_file "$TMP_DIR/syn-mdm-editor.payload.json"
    printf -- '---\n'
    check_contains "синтетика: syn-mdm-editor realm_access.roles содержит mdm:read" \
        "$syn_mdm_editor_payload" '"mdm:read"'
    check_contains "синтетика: syn-mdm-editor realm_access.roles содержит mdm:write" \
        "$syn_mdm_editor_payload" '"mdm:write"'
    check_claim_equals "синтетика: syn-mdm-editor org_id = $ORG_ID_A" \
        "$syn_mdm_editor_payload" "org_id" "$ORG_ID_A"
    check_contains "синтетика: syn-mdm-editor groups содержит /reon/hq" \
        "$syn_mdm_editor_payload" '"/reon/hq"'
else
    bad "синтетика: syn-mdm-editor ROPC вернул HTTP $code"
    bad "синтетика: syn-mdm-editor realm_access.roles содержит mdm:read (нет токена)"
    bad "синтетика: syn-mdm-editor realm_access.roles содержит mdm:write (нет токена)"
    bad "синтетика: syn-mdm-editor org_id не проверен (нет токена)"
    bad "синтетика: syn-mdm-editor groups не проверен (нет токена)"
fi

# d) syn-branch-employee-1: только чтение, организация B
printf '\n-- синтетический пользователь syn-branch-employee-1 --\n'
code="$(post_token "$TMP_DIR/syn-branch-employee-1.json" \
    -d grant_type=password \
    -d client_id="$SMOKE_CLIENT_ID" \
    --data-urlencode "client_secret=$SMOKE_CLIENT_SECRET" \
    -d username=syn-branch-employee-1 \
    --data-urlencode "password=syn-branch-employee-1-pass" \
    -d scope=openid)"
code="${code:-000}"
syn_branch_token=""
if [ "$code" = "200" ]; then
    syn_branch_token="$(json_access_token "$TMP_DIR/syn-branch-employee-1.json")"
fi

if [ -n "$syn_branch_token" ]; then
    ok "синтетика: syn-branch-employee-1 вернул токен (ROPC, HTTP 200)"
    jwt_payload "$syn_branch_token" >"$TMP_DIR/syn-branch-employee-1.payload.json"
    syn_branch_payload="$(cat "$TMP_DIR/syn-branch-employee-1.payload.json")"
    printf -- '--- claims access-токена syn-branch-employee-1 ---\n'
    pretty_file "$TMP_DIR/syn-branch-employee-1.payload.json"
    printf -- '---\n'
    check_not_contains "синтетика: syn-branch-employee-1 realm_access.roles НЕ содержит mdm:write" \
        "$syn_branch_payload" '"mdm:write"'
    check_claim_equals "синтетика: syn-branch-employee-1 org_id = $ORG_ID_B" \
        "$syn_branch_payload" "org_id" "$ORG_ID_B"
else
    bad "синтетика: syn-branch-employee-1 ROPC вернул HTTP $code"
    bad "синтетика: syn-branch-employee-1 realm_access.roles НЕ содержит mdm:write (нет токена)"
    bad "синтетика: syn-branch-employee-1 org_id не проверен (нет токена)"
fi

# ---------------------------------------------------------------------------
# Итог
# ---------------------------------------------------------------------------
printf '\n=== Итог: PASS=%d FAIL=%d ===\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
    printf 'Smoke-проверка НЕ пройдена.\n'
    exit 1
fi
printf 'Smoke-проверка пройдена.\n'
