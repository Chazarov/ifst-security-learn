# Развёртывание bWAPP (Docker)

Образ: `hackersploit/bwapp-docker` (Apache + PHP + MySQL в одном контейнере).

## Запуск

```powershell
cd labs/7/resolve
docker compose up -d
```

## Первичная настройка

1. Откройте http://localhost:8080/install.php
2. Нажмите **Click here to install bWAPP** (настройки БД уже внутри контейнера).
3. После установки: http://localhost:8080/login.php

**Логин по умолчанию:** `bee` / `bug`

В меню bWAPP выберите уровень **low** для демонстрации атак.

## Остановка

```powershell
docker compose down
```
