# Сервис информации об угрозах

Тестовое задание на Go. Сервис хранит информацию об угрозах в PostgreSQL.
Есть три метода:

- `POST /info` — добавить угрозу;
- `GET /info/{md5}` — получить запись;
- `PUT /info/{md5}` — заменить данные существующей записи.

Использовал `net/http`, `pgx`, `goose` и `oapi-codegen`.
Спецификация лежит в [api/openapi.yaml](api/openapi.yaml).

## Запуск

Нужны Docker и Docker Compose.

```sh
cp .env.example .env
```

В `.env` нужно заполнить `API_KEY` и `POSTGRES_PASSWORD`.
Для каждого значения можно отдельно выполнить `openssl rand -hex 32`.

```sh
docker compose up --build -d
```

Сервис будет доступен на `http://localhost:8080`. Таблицы создаются автоматически
при запуске. Данные сохраняются между перезапусками.

Остановить сервис:

```sh
docker compose down
```

## Примеры запросов

Сначала указать ключ из `.env`:

```sh
export API_KEY='ключ-из-env'
```

Добавить угрозу:

```sh
curl -i http://localhost:8080/info \
  -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","type":"trojan","severity":"high","description":"Крадёт учётные данные","tags":["windows"]}'
```

Получить запись:

```sh
curl http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H "X-API-Key: $API_KEY"
```

Обновить запись:

```sh
curl -i -X PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Worm.Win32.Example","type":"worm","severity":"critical"}'
```

Обязательные поля: `name`, `type`, `severity`, а при создании ещё `md5`.
Дополнительно можно передать `description` и `tags`.
`created_at` и `updated_at` заполняются сервером.

MD5 проверяется и приводится к нижнему регистру. Повторное создание возвращает
`409`, отсутствующая запись — `404`, некорректные данные — `400`.
`PUT` заменяет данные целиком: если не передать описание и метки, они очищаются.

Для доступа нужен заголовок `X-API-Key`. По умолчанию лимит — 60 запросов в минуту
на IP. HTTPS включается через `TLS_CERT_FILE` и `TLS_KEY_FILE` при локальном запуске.

## Разработка и тесты

Для запуска без Docker нужны Go 1.26+ и PostgreSQL 14+ с созданной базой.

```sh
export DATABASE_URL='postgres://user:password@localhost:5432/threats?sslmode=disable'
export API_KEY="$(openssl rand -hex 32)"
make run
```

Настройки читаются из переменных окружения. При локальном запуске `.env`
автоматически не загружается.

```sh
make test        # Unit- и HTTP-тесты
make lint        # Линтер
make build       # Сборка в bin/server
make generate    # Генерация кода после изменения спецификации
```

Для интеграционных тестов нужна отдельная тестовая БД. Пользователю нужны права
на создание схем. Тесты создают свою схему и удаляют её после завершения.

```sh
export TEST_DATABASE_URL='postgres://user:password@localhost:5432/threats_test?sslmode=disable'
make integration
```
