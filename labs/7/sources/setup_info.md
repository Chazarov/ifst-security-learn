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

Шесть примеров атак и пошаговые инструкции: **sources/usage.md**.  
Скрипты и payload: **resolve/attacks/** и **resolve/csrf_attack/**.

## CSRF-демо

Папка: `resolve/csrf_attack/`

Цель запроса: `POST http://localhost/password_change.php`  
Поля: `password_curr`, `password_new`, `password_conf`, `action=change`

**basic.html** — базовый пример, кнопка отправляет скрытую форму.

**index.html** — поддельная страница входа, по кнопке Login уходит тот же POST.

1. Войти в bWAPP (`bee` / `bug`), security **low**, не выходить.
2. Открыть `basic.html` или `index.html` (при другом порте bWAPP — поменять URL в `<script>` в файле).
3. Отправить запрос — пароль станет `csrf_hacked` (текущий пароль в форме: `bug`).
4. Проверить вход на http://localhost/login.php

Если bWAPP в Docker на порту 8080: в HTML замените `http://localhost` на `http://localhost:8080`.

## Остановка

```powershell
docker compose down
```
