#!/bin/sh
# One-shot применение синтетических данных DEV-стенда ИС РЕОН 2.0.
#
# Запускается сервисом reon-auth-synthetic-init (образ curlimages/curl, /bin/sh).
# Делает ровно одно: POST /admin/realms/<realm>/partialImport с телом
# /data/reon-synthetic.json, где секреты клиентов подставлены из окружения.
#
# Почему partial import, а не --import-realm: realm уже создан из тома Postgres,
# а partial import работает поверх существующего realm и идемпотентен при
# "ifResourceExists": "SKIP".
#
# Переменные окружения (значения по умолчанию заданы в docker-compose.yml):
#   KEYCLOAK_URL, KEYCLOAK_USER, KEYCLOAK_PASSWORD, REALM,
#   MDM_SERVICE_CLIENT_SECRET, REON_S3_SERVER_CLIENT_SECRET,
#   REON_PROCESS_BACKEND_CLIENT_SECRET

set -eu

KEYCLOAK_URL="${KEYCLOAK_URL:-http://reon-auth-keycloak:8080}"
KEYCLOAK_USER="${KEYCLOAK_USER:-admin}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:-dev-admin-change-me}"
REALM="${REALM:-reon}"
SOURCE_FILE="/data/reon-synthetic.json"
WORK_FILE="/tmp/reon-synthetic.json"
RESPONSE_FILE="/tmp/partial-import-response.json"

fail() {
    printf 'ОШИБКА: %s\n' "$*" >&2
    exit 1
}

[ -f "$SOURCE_FILE" ] || fail "не найден $SOURCE_FILE (проверьте монтирование ./docker/keycloak/synthetic:/data:ro)"

# --- 1. Подстановка секретов клиентов из окружения -------------------------
# В репозитории лежат только плейсхолдеры; значения по умолчанию — DEV-заглушки.
sed \
    -e "s|__MDM_SERVICE_CLIENT_SECRET__|${MDM_SERVICE_CLIENT_SECRET:-}|g" \
    -e "s|__REON_S3_SERVER_CLIENT_SECRET__|${REON_S3_SERVER_CLIENT_SECRET:-}|g" \
    -e "s|__REON_PROCESS_BACKEND_CLIENT_SECRET__|${REON_PROCESS_BACKEND_CLIENT_SECRET:-}|g" \
    "$SOURCE_FILE" >"$WORK_FILE"

if grep -q '__[A-Z0-9_]*__' "$WORK_FILE"; then
    fail "в $SOURCE_FILE остались неподставленные плейсхолдеры (проверьте переменные окружения секретов)"
fi

# --- 2. Готовность realm (после reon-auth-keycloak-init) -------------------
printf 'Ожидание realm %s в %s...\n' "$REALM" "$KEYCLOAK_URL"
realm_ready=0
for _ in $(seq 1 60); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
        "$KEYCLOAK_URL/realms/$REALM/.well-known/openid-configuration" 2>/dev/null || echo 000)"
    if [ "$code" = "200" ]; then
        realm_ready=1
        break
    fi
    sleep 2
done
if [ "$realm_ready" -ne 1 ]; then
    fail "realm $REALM недоступен (HTTP $code). Сначала примените базовый realm: docker compose run --rm reon-auth-keycloak-init"
fi

# --- 3. Токен администратора master realm ----------------------------------
token_response="$(curl -sS -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d grant_type=password \
    -d client_id=admin-cli \
    --data-urlencode "username=$KEYCLOAK_USER" \
    --data-urlencode "password=$KEYCLOAK_PASSWORD" 2>&1)" || fail "не выполнен запрос токена администратора: $token_response"

admin_token="$(printf '%s' "$token_response" | tr -d '\n' \
    | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [ -z "$admin_token" ]; then
    fail "не получен access_token администратора (проверьте KEYCLOAK_USER/KEYCLOAK_PASSWORD): $token_response"
fi

# --- 4. Partial import ------------------------------------------------------
printf 'Применение %s (ifResourceExists: SKIP)...\n' "$SOURCE_FILE"
http_code="$(curl -sS -o "$RESPONSE_FILE" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    --data-binary "@$WORK_FILE" \
    "$KEYCLOAK_URL/admin/realms/$REALM/partialImport" 2>&1)" || fail "запрос partialImport не выполнен"
http_code="${http_code:-000}"

printf 'HTTP %s, ответ Keycloak:\n' "$http_code"
if [ -s "$RESPONSE_FILE" ]; then
    cat "$RESPONSE_FILE"
    printf '\n'
else
    printf '(пустой ответ)\n'
fi

if [ "$http_code" != "200" ]; then
    fail "partialImport вернул HTTP $http_code (см. ответ выше)"
fi

# --- 5. Service accounts сервисных клиентов --------------------------------
# Partial import создаёт клиента, но не создаёт его service account user
# (в Keycloak 26.5.5 это отдельный шаг). Без него client_credentials отвечает
# 401 "The associated service account for the client does not exist".
# Штатный Admin API создаёт service account при первом GET .../service-account-user,
# повторный вызов идемпотентен.
for cid in mdm-service reon-s3-server reon-process-backend; do
    client_id="$(curl -sS -H "Authorization: Bearer $admin_token" \
        "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=$cid" \
        | tr -d '\n' | grep -o '"id":"[0-9a-f-]*"' | head -n 1 | cut -d '"' -f 4)"
    if [ -z "$client_id" ]; then
        fail "клиент $cid не найден в realm $REALM после partial import"
    fi
    sa_code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $admin_token" \
        "$KEYCLOAK_URL/admin/realms/$REALM/clients/$client_id/service-account-user" 2>/dev/null || echo 000)"
    if [ "$sa_code" != "200" ]; then
        fail "не удалось подготовить service account клиента $cid (HTTP $sa_code)"
    fi
    printf 'Service account клиента %s готов (HTTP 200).\n' "$cid"
done

printf 'Синтетические клиенты и пользователи применены (realm %s).\n' "$REALM"
