# Лабораторная 7 — шесть примеров атак на bWAPP

Перед началом: bWAPP установлен, вход bee/bug, уровень безопасности low. Базовый URL — http://localhost (Docker: http://localhost:8080). Материалы: папка labs/7/resolve/attacks/ и labs/7/resolve/csrf_attack/.

---

## 1. SQL Injection (вход без пароля)

Суть: ввод в поле логина попадает в SQL-запрос без экранирования; условие всегда истинно — сервер пускает без знания пароля.

Где в bWAPP: меню SQL Injection → SQLi (Login Forms / Login) / Hero.

Материалы: attacks/01_sqli_payloads.txt

Шаги:
1. Открыть страницу SQLi login, не входить заранее.
2. Login: скопировать из файла, например `' OR 1=1--`
3. Password: любой символ или пусто.
4. Submit — должен открыться интерфейс от имени пользователя (часто admin или bee).

Скрин: форма с payload и успешный вход.

Защита: prepared statements (параметризованные запросы), ORM, не собирать SQL конкатенацией; минимальные права БД.

---

## 2. XSS (Reflected)

Суть: приложение выводит ваш ввод в HTML без экранирования; браузер выполняет JavaScript.

Где: XSS → Reflected (GET/POST), уровень low.

Материалы: attacks/02_xss_payloads.txt, attacks/02_xss_demo.html

Шаги (вручную):
1. Открыть XSS Reflected GET.
2. В поле (часто firstname/name/title) вставить `<script>alert('XSS')</script>` из payloads.
3. Отправить — должен появиться alert.

Шаги (скрипт-страница):
1. В 02_xss_demo.html при другом хосте поменять переменную BWAPP.
2. Открыть файл в браузере, кнопка «Открыть payload» — откроется xss_get.php с внедрённым скриптом (путь может отличаться в вашей версии; тогда вставьте payload вручную на странице bWAPP).

Защита: htmlspecialchars при выводе, Content-Security-Policy, HttpOnly для cookie сессии.

---

## 3. CSRF (смена пароля)

Суть: жертва залогинена; ваша страница отправляет POST на password_change.php; браузер прикрепляет PHPSESSID; пароль меняется без согласия.

Где: уязвимость на password_change.php (раздел CSRF / Change Password в меню, если есть).

Материалы: csrf_attack/basic.html, csrf_attack/index.html

Шаги:
1. Войти в bWAPP bee/bug, не выходить.
2. Открыть basic.html (или index.html с поддельным логином).
3. В HTML указать верный BWAPP (http://localhost или :8080).
4. Нажать кнопку отправки — в скрытой форме POST: password_curr=bug, password_new=csrf_hacked, password_conf=csrf_hacked, action=change.
5. Выйти и войти с паролем csrf_hacked.

Защита: CSRF-токен в форме, SameSite cookie, проверка Origin/Referer, повторный ввод текущего пароля.

---

## 4. OS Command Injection

Суть: поле «IP для ping» передаётся в системную команду shell; метасимволы ; && | выполняют произвольные команды ОС.

Где: Injection → OS Command Injection (ping).

Материалы: attacks/04_cmd_payloads.txt

Шаги:
1. Открыть страницу ping, security low.
2. В поле target/host ввести: `127.0.0.1; whoami` (Linux) или `127.0.0.1 & whoami` (Windows в контейнере часто Linux).
3. Submit — в ответе кроме ping виден вывод whoami или списка файлов (dir, ls).

Скрин: поле с payload и фрагмент вывода команды.

Защита: не вызывать shell с пользовательским вводом; whitelist IP; escapeshellarg; отдельный сервис без shell.

---

## 5. Unrestricted File Upload

Суть: сервер принимает загрузку файла с опасным расширением (.php); файл кладётся в доступную из web каталог — возможно выполнение кода.

Где: Unrestricted File Upload / File Upload.

Материалы: attacks/05_upload_test.php.txt

Шаги:
1. Сохранить содержимое файла как upload_test.php (убрать .txt).
2. В bWAPP выбрать этот файл и загрузить (low).
3. Открыть URL загруженного файла из сообщения на странице — на экране LAB7_UPLOAD_OK.

Защита: белый список расширений и MIME, хранение вне document root, переименование, антивирус, без выполнения в каталоге uploads.

---

## 6. IDOR (Insecure Direct Object References)

Суть: в URL или форме идентификатор объекта (id, ticket_id) без проверки прав; смена числа открывает чужие данные.

Где: Insecure Direct Object References в меню (ir_idor, xxe с id=, tickets и т.д. — зависит от версии).

Материалы: attacks/06_idor_urls.txt

Шаги:
1. Войти как bee.
2. Открыть страницу с параметром id=1 или ticket_id=1 (из подсказок в меню).
3. В адресной строке заменить на id=2, id=3 — сравнить данные на странице (чужой заказ, запись, файл).

Скрин: URL с id=1 и id=2 с разным содержимым.

Защита: на сервере проверять, что объект принадлежит текущему пользователю; непредсказуемые ID (UUID); авторизация на каждый запрос.

---

## Что сдать на защите

По каждой из шести атак: название, скрин «до/после», кратко механизм, мера защиты. Показать хотя бы одну атаку с готовым скриптом (CSRF basic.html или XSS demo). Указать, где в браузере хранится сессия (cookie PHPSESSID) и риск при XSS/CSRF.

## Настройка URL

Файл attacks/config.txt — подставьте свой BWAPP. Во всех .html в csrf_attack и attacks поменяйте http://localhost на http://localhost:8080 при работе через docker-compose из labs/7/resolve.

## Если страница bWAPP не найдена

Имена файлов (xss_get.php, sqli_*.php) могут отличаться в вашей сборке. Используйте поиск по меню слева в bWAPP по типу уязвимости; payload из txt-файлов переносите в соответствующую форму.
