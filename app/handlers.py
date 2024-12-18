import os
from dotenv import load_dotenv
import requests
import time
from io import BytesIO
from aiogram import Router, F
from aiogram.filters import CommandStart
from aiogram.types import Message, ContentType

router = Router()

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"

# Загрузить переменные из .env
load_dotenv()

# Получить ключ
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def scan_url(url: str) -> str:
    """
    Сканирование ссылки через VirusTotal API.

    Args:
        url (str): Ссылка для сканирования.

    Returns:
        str: Результат сканирования в виде строки.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post(
        f"{VIRUSTOTAL_URL}/urls", headers=headers, data={"url": url}
    )
    result = response.json()

    time.sleep(10)

    if response.status_code == 200:
        analysis_id = result["data"]["id"]
        analysis_response = requests.get(
            f"{VIRUSTOTAL_URL}/analyses/{analysis_id}", headers=headers
        )
        analysis_result = analysis_response.json()

        if analysis_response.status_code == 200:
            stats = analysis_result["data"]["attributes"]["stats"]
            return (
                (
                    f"✅ <b>Всё в порядке, ни один из антивирусов не посчитал эту ссылку подозрительной</b>\n\n"
                )
                if stats["suspicious"] == 0 and stats["malicious"] == 0
                else (
                    f"❗️<b>Не все антивирусы посчитали ссылку безопасной</b>\n\n"
                    f"✅ Безопасно: {stats['harmless']}\n\n"
                    f"🤔 Подозрительно: {stats['suspicious']}\n\n"
                    f"⛔️ Вредоносно: {stats['malicious']}\n\n"
                )
            )
        else:
            return f"🤖 Ошибка при получении результатов анализа: {analysis_result.get('error', 'Неизвестная ошибка')} {response.status_code}"
    else:
        return f"🤖 <b>Ошибка при проверке ссылки, проверьте правильность введённой ссылки</b>"


def scan_file(file: BytesIO, file_name: str) -> str:
    """
    Сканирование файла через VirusTotal API.

    Args:
        file (BytesIO): Файл для сканирования в виде объекта BytesIO.
        file_name (str): Имя файла.

    Returns:
        str: Результат сканирования в виде строки.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (file_name, file)}
    response = requests.post(f"{VIRUSTOTAL_URL}/files", headers=headers, files=files)
    result = response.json()

    if response.status_code == 200:
        analysis_id = result["data"]["id"]
        analysis_response = requests.get(
            f"{VIRUSTOTAL_URL}/analyses/{analysis_id}", headers=headers
        )
        analysis_result = analysis_response.json()

        if analysis_response.status_code == 200:
            stats = analysis_result["data"]["attributes"]["stats"]
            return (
                (
                    f"✅ <b>Всё в порядке, ни один из антивирусов не посчитал этот файл подозрительным</b>\n\n"
                )
                if stats["suspicious"] == 0 and stats["malicious"] == 0
                else (
                    f"❗️<b>Не все антивирусы посчитали файл безопасным</b>\n\n"
                    f"✅ Безопасно: {stats['harmless']}\n\n"
                    f"🤔 Подозрительно: {stats['suspicious']}\n\n"
                    f"⛔️ Вредоносно: {stats['malicious']}\n\n"
                )
            )
        else:
            return f"🤖 Ошибка при получении результатов анализа: {analysis_result.get('error', 'Неизвестная ошибка')} {response.status_code}"
    else:
        return f"🤖 <b>Ошибка при проверке файла, проверьте правильность введённого файла</b>"


@router.message(CommandStart())
async def command_start_handler(message: Message):
    """
    Обработчик команды /start.

    Args:
        message (Message): Сообщение от пользователя.
    """
    await message.answer(
        f"👋 Приветствую, {message.from_user.full_name}! "
        f"Отправьте ссылку или файл для проверки."
    )


@router.message(F.text.regexp(r"(http[s]?://)?[^\s]+"))
async def handle_link(message: Message):
    """
    Обработка строки-ссылки.

    Args:
        message (Message): Сообщение от пользователя, содержащее ссылку.
    """
    link = message.text.strip()
    # Удаляем протокол, если он есть
    link = link.replace("http://", "").replace("https://", "").replace("ftp://", "")
    wait_message = await message.answer(
        "🔄 Пожалуйста, подождите, идет проверка ссылки..."
    )
    result = scan_url(link)
    await message.answer(result, parse_mode="HTML")
    await wait_message.delete()


@router.message(F.content_type == ContentType.DOCUMENT)
async def handle_document(message: Message):
    """
    Обработка документа.

    Args:
        message (Message): Сообщение от пользователя, содержащее документ.
    """
    document = message.document
    file_info = await message.bot.get_file(document.file_id)
    file = await message.bot.download_file(file_info.file_path)
    file_bytes = BytesIO(file.read())
    wait_message = await message.answer(
        "🔄 Пожалуйста, подождите, идет проверка файла..."
    )
    result = scan_file(file_bytes, document.file_name)
    await message.answer(result, parse_mode="HTML")
    await wait_message.delete()


@router.message()
async def handle_unrecognized(message: Message):
    """
    Обработка нераспознанных сообщений.

    Args:
        message (Message): Сообщение от пользователя, которое не удалось распознать.
    """
    await message.answer("🤖 Не могу распознать, отправьте файл или ссылку.")
