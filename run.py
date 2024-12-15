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

# все хендлеры должны быть прикреплены к роутеру/диспетчеру
TOKEN = os.getenv("TOKEN")
dp = Dispatcher()


async def main() -> None:
    dp.include_router(router)

    # инициализация бота
    bot = Bot(token=TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))

    # старт
    await dp.start_polling(bot)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, stream=sys.stdout
    )  # убрать перед продакшеном (логирование)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot Stopped")
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)
