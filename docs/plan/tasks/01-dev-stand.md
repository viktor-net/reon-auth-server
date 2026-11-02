# Задача 01 — DEV-стенд: общий Keycloak, nginx и realm как код

- task-id: `local-20261101-01`
- size: **M**
- статус: **закрыта** (reviewer-2: «принять с рисками», reduce и close в журнале)
- зависимости: нет
- доска: `.agents/tasks/local-20261101-01/`

## Зачем

Всем модулям и административному фронтенду нужна единая точка аутентификации,
которую можно поднять из чистого клона и на которой можно проверять контракт
токенов. Своего кода аутентификации не пишем: всё закрывает настроенный
Keycloak.

## Что входит

1. **Compose-стенд.** Postgres, Keycloak 26.5.5, nginx как точка входа.
   Порты: nginx 8090, Keycloak 8084, Postgres 5434 (8080-8082 и 5433 заняты
   смежным стендом `reon-s3-*`).
2. **Realm как код.** `docker/keycloak/realm.yml` и `dev-users.yml`
   применяются one-shot сервисом `reon-auth-keycloak-init` через
   `keycloak-config-cli`; повторный запуск идемпотентен.
3. **Клиенты realm `reon`.** `reon-admin-web` (public, Authorization Code
   с PKCE S256), `reon-api` (аудитория), `reon-service` (client_credentials),
   `reon-dev-smoke` (ROPC, только DEV).
4. **Орг-структура и права.** Группы орг-дерева (`/reon/hq`,
   `/reon/hq/finance`, ...), capabilities-роли на группах, служебная группа
   `/reon/admins` с `MASTER_ADMIN`, атрибут `org_id` у групп и DEV-зеркало
   атрибута на пользователях (штатный `oidc-usermodel-attribute-mapper`).
5. **Smoke.** `scripts/smoke-auth.sh` и `scripts/smoke-auth.ps1` — паритетные
   проверки (52 в каждом): discovery, выдача токенов, claims, группы, роли,
   TTL, redirect URIs, крупный заголовок через nginx.
6. **Секреты.** Только dev-образцы в `.env.example`; реальные значения — в
   локальном `.env`, который не коммитится.

## Что не входит

- Собственный код аутентификации и авторизации: вход полностью закрывает Keycloak.
- Продуктовые практики: TLS, продуктовые TTL, отключение ROPC (задача 08).
- СУДИР (задача 05), BFF (задача 06).

## Файлы

`docker-compose.yml`, `docker/keycloak/**`, `docker/nginx/nginx.conf`,
`scripts/smoke-auth.sh`, `scripts/smoke-auth.ps1`, `.env.example`.

## Критерии приёмки

- [x] Стенд поднимается `docker compose up -d` из чистого клона.
- [x] Init идемпотентен, повторный запуск не меняет realm.
- [x] Smoke bash и pwsh: 52/52, 0 FAIL.
- [x] Секретов в репозитории нет.
- [x] Контракт токенов описан и воспроизводим.

## Итог и принятые решения

- `org_id` выдаётся штатным attribute-mapper из DEV-зеркала атрибута на
  пользователе: скрипт-маппер и `KC_FEATURES=scripts` не используются
  (отклонение от `brief.v2` ратифицировано в reduce).
- `MASTER_ADMIN` вынесен на отдельную группу `/reon/admins`, иначе роль
  наследовалась бы всей ветке `/reon/hq`.
- Клиент `reon-web` исключён: BFF отложен, прямой ход SPA — временная схема.

## Риски, переданные дальше

- `keycloak-config-cli` не удаляет роли и членство, убранные из конфига:
  правки «на удаление» на живом стенде требуют точечной очистки через Admin
  API; чистый клон воспроизводится корректно.
- `/admin/` Keycloak доступен через nginx на DEV — закрывается в задаче 08.
- ROPC включён у `reon-dev-smoke`: в продуктовых интеграциях запрещён.
- Smoke не проверяет просроченный/чужой токен и обязательность PKCE на
  `/auth` — усиление в задачах 03 и 08.
