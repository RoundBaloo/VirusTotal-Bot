# URL and file analysis Telegram bot (VirusTotal)

## Описание
Telegram бот, который умеет обрабывать ссылки и файлы через VirusTotal API. Если по объекту есть подозрения - бот сообщит информацию о количестве антивирусных движков, которые посчитали объект небезопасным.

## Подготовка окружения для разработки (Windows)
- python -m venv .venv
- .venv/Scripts/activate
- pip install -r requirements.txt
- создайте файл .env в корне проекта, используя шаблон config_example.env
- заполните .env своими API-ключами

## Запуск приложения локально (без Docker)
- python run.py

## Запуск приложения локально (с Docker)
- docker compose up --build

## Остановка и очистка
- остановка командой `docker compose down`
- после нескольких тестовых сборок можно почистить образы/контейнеры которые накопились: `docker system prune`