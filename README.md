# URL and file analysis Telegram bot (VirusTotal)

## Описание
### Telegram бот, который умеет обрабывать ссылки и файлы через VirusTotal API, проверяя их на вредоносность.

### Если отправленные боту файл или ссылка будут классифицированы VirusTotal API как безопасные, то бот уведомит пользователя об этом сообщением:

✅ Всё в порядке, ни один из антивирусов не посчитал этот файл подозрительным

### Если по объекту есть подозрения - бот сообщит информацию о количестве антивирусных движков, которые посчитали объект небезопасным в формате:

❗️Не все антивирусы посчитали файл безопасным

✅ Безопасно: <число движков>

🤔 Подозрительно: <число движков>

⛔️ Вредоносно: <число движков>

### Так как обработка объекта не моментальная, после его отправки бот вышлет сообщение (оно будет удалено, когда бот пришлет результаты анализа) с просьбой ожидать конца обработки:

🔄 Пожалуйста, подождите, идет проверка ссылки...

### При отправке того, что бот не может распознать, он уведомит о том, что ввод неверный и следует проверить свой запрос:

🤖 Не могу распознать, отправьте файл или ссылку.

### При ошибке в самой ссылке/файле бот пришлет сообщение:

🤖 Ошибка при проверке ссылки/файла, проверьте правильность введённой ссылки

### При ошибке во время анализа файла/ссылки бот пришлет сообщение:

🤖 Ошибка при получении результатов анализа: <данные об ошибке>"



## Подготовка окружения для разработки (Windows)
- создать виртуальное окружение `python -m venv .venv`
- активировать виртуальное окружение `.venv/Scripts/activate`
- установить в виртуальное окружение все нужные библиотеки `pip install -r requirements.txt`
- создать файл .env в корне проекта, используя шаблон config_example.env
- заполнить .env своими API-ключами

## Запуск приложения локально (без Docker)
- запуск с помощью команды `python run.py`

## Остановка приложения локально (без Docker)
- остановка с помощью команды сочетания клавиш Ctrl+C

## Запуск приложения локально (с Docker)
- запуск с помощью команды `docker compose up --build`

## Остановка и очистка
- остановка командой `docker compose down`
- после нескольких тестовых сборок можно почистить образы/контейнеры которые накопились: `docker system prune` или `docker container prune`