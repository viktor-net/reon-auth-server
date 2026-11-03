# Changelog

История изменений репозитория. Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).

Изменения ниже касаются **только документации API**. 
Keycloak живут на `/realms/{realm}/..`, административные — на
`/admin/realms/{realm}/..`

### Добавлено

- Документация API: интроспекция токена —
  `POST /realms/{realm}/protocol/openid-connect/token/introspect`.
- Документация API: отзыв токена —
  `POST /realms/{realm}/protocol/openid-connect/revoke`.
- Документация API: Admin-мутации для воркера синхронизации орг-структуры
  (задача 04):
  - `POST /admin/realms/{realm}/users` — создание пользователя;
  - `PUT` и `DELETE /admin/realms/{realm}/users/{user-id}/groups/{group-id}` —
    включение пользователя в группу и исключение из неё;
  - `POST` и `DELETE /admin/realms/{realm}/users/{user-id}/role-mappings/realm` —
    назначение и снятие realm-ролей;
  - `POST /admin/realms/{realm}/groups` — создание корневой группы;
  - `POST /admin/realms/{realm}/groups/{group-id}/children` — создание
    подгруппы;
  - `PUT` и `DELETE /admin/realms/{realm}/groups/{group-id}` — обновление и
    удаление группы.
- Документация API: компоненты `Realm` (общий path-параметр), `Conflict`
  (ответ 409) и `IntrospectionResponse`.
- `CHANGELOG.md` — этот файл.

### Изменено

- Документация API: пути приведены к оригинальному виду Keycloak 26.5 с
  параметром `{realm}` вместо хардкода `reon`/`master`. В примерах
  параметра — `reon` (рабочий realm) и `master` (админ-токен), поэтому
  «Try it» в Scalar работает без подготовки.
- Документация API: выдача админ-токена перенесена в общий token-эндпоинт
  (пример `adminPassword`, `realm=master`).
- Документация API: summary методов сокращены — «Список пользователей»,
  «Дерево групп», «Список клиентов», «Клиент по UUID», «Сброс пароля» и
  другие.
- Документация API: публичные операции получили явный `security: []`
  (аутентификация не требуется либо клиентская), добавлена ссылка на
  официальную OpenAPI-спецификацию Keycloak.
- `README.md`: раздел «Документация API (Scalar)» описывает оригинальные
  пути с `{realm}`, интроспекцию и отзыв токенов, мутации Admin API и пример
  `adminPassword`.

### Удалено

- Документация API: отдельный путь
  `/realms/master/protocol/openid-connect/token` и операция
  `issueAdminToken`. Они заменены примером `adminPassword` в общем
  token-эндпоинте — админ-токен выдаётся там же, где и все остальные.

## [0.1.0] — 2026-11-02

Первый воспроизводимый DEV-стенд аутентификации.

### Добавлено

- Docker Compose стенд: Keycloak 26.5.5, Postgres 16, nginx — единая точка
  входа `http://localhost:10010`, Scalar — документация `/docs/`, one-shot
  сервисы инициализации realm и синтетических данных.
- Realm `reon` как код (`docker/keycloak/`): клиенты `reon-admin-web`,
  `reon-service`, `reon-api`, `reon-dev-smoke`, dev-пользователи и дерево
  групп с ролями и атрибутом `org_id`.
- Синтетические клиенты сервисов и 12 пользователей для проверки сценариев
  модулей.
- Smoke-проверки контракта токенов: `scripts/smoke-auth.sh` и
  `scripts/smoke-auth.ps1`.
- Документация API (Scalar) с интерактивными запросами к стенду.
- Архитектурные документы: ADR, стандарт подключения сервисов, дорожная
  карта задач.
- Страница-указатель на `http://localhost:10010/` со ссылками на рабочие
  адреса стенда.

### Изменено

- Адрес issuer и адрес консоли администратора разделены: публичный адрес —
  через `KC_HOSTNAME` (nginx, порт 10010), консоль — через
  `KC_HOSTNAME_ADMIN` (прямой порт 10009).
- Опубликованные порты стенда переведены на последовательные `10008–10011`;
  диапазон `10000–10007` занят смежным стендом `reon-s3-*`.
