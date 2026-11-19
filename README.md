# Стобальные выступления — «Ну-ка, все вместе!»

Небольшой адаптивный сайт-каталог выступлений, набравших 100 баллов.

## Запуск
Откройте `index.html` в браузере. Сборка и установка зависимостей не требуются.

## Панель администратора
- Нажмите **Numpad 8** (клавиша 8 на цифровом блоке клавиатуры).
- Пароль: `nukaadmin`.
- Добавляйте, редактируйте и удаляйте участников.
- Для каждого выступления укажите имя, фамилию, сезон, песню и при желании фотографию.
- Публичная страница позволяет фильтровать выступления по сезону.

## Общее хранилище участников
- Публичный архив загружается из файла `participants.json` в репозитории. Все посетители сайта получают один и тот же список независимо от устройства.
- Администратор может добавлять, редактировать и удалять записи в текущем сеансе, импортировать JSON и скачивать обновлённый `participants.json`.
- После изменений скачайте файл из админ-панели и замените им `participants.json` в GitHub. После публикации коммита обновлённый архив станет общим для всех посетителей.
- Для переноса прежних записей, сохранённых локально на старом компьютере, откройте админ-панель именно в том браузере, где они были созданы, нажмите «Перенести архив этого браузера», затем скачайте JSON и загрузите его в репозиторий.
- Фотографии в JSON сохраняются как оптимизированные JPEG-данные.

## Важно о доступе
Это простой локальный административный интерфейс для небольшого личного проекта. Пароль находится в клиентском JavaScript, поэтому он **не обеспечивает настоящую защиту**: посетитель может посмотреть исходный код и данные браузера. Для публичного сайта с реальными правами доступа нужен сервер, авторизация и база данных.


## Cloudflare backend (in progress)

A server-side backend is being prepared in `worker/`:
- Cloudflare Workers API for reading the public archive and authenticating administrators.
- Cloudflare D1 for the shared archive.
- Cloudflare R2 for participant photos and galleries.
- GitHub Actions workflow for automatic Worker deployment.

Setup instructions: [worker/README.md](worker/README.md).

**The live frontend has not been switched to the API yet.** First create the Cloudflare D1 database and R2 bucket, add the Cloudflare secrets to GitHub Actions, configure the Worker secrets, and deploy the Worker. Then the frontend can be connected and the existing archive migrated safely.

The repository's `participants.json` currently appears empty through the GitHub file API. Before importing data, locate or export the real archive and make a backup.
