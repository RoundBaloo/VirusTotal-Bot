import os
from dotenv import load_dotenv
import asyncio
import logging
import sys
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from app.handlers import router

# Загрузить переменные из .env
load_dotenv()

# Все хендлеры должны быть прикреплены к роутеру/диспетчеру
TOKEN = os.getenv("TOKEN")
dp = Dispatcher()


async def main() -> None:
    """
    Основная асинхронная функция для запуска бота.

    Эта функция включает роутер, инициализирует бота и запускает процесс
    обработки событий (polling).
    """
    dp.include_router(router)

    # Инициализация бота
    bot = Bot(token=TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))

    # старт
    await dp.start_polling(bot)


if __name__ == "__main__":
    """
    Точка входа в приложение.

    Эта часть кода выполняется при запуске скрипта напрямую. Она настраивает
    логирование и запускает основную асинхронную функцию main().
    """
    # Убрать перед продакшеном (логирование)
    # logging.basicConfig(
    #     level=logging.INFO, stream=sys.stdout
    # )
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot Stopped")
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)
