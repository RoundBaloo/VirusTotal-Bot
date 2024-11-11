import requests
from aiogram import Router, F
from aiogram.filters import CommandStart
from aiogram.types import Message, ContentType
from config import VIRUSTOTAL_API_KEY

router = Router()

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"


def scan_url(url: str) -> str:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post(
        f"{VIRUSTOTAL_URL}/urls", headers=headers, data={"url": url}
    )
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
                    f"✅ <b>Всё в порядке, ни один из антивирусов не посчитал эту ссылку подозрительной</b>\n\n"
                    # f"✅ Безопасно: {stats['harmless']}\n\n"
                    # f"🤔 Подозрительно: {stats['suspicious']}\n\n"
                    # f"⛔️ Вредоносно: {stats['malicious']}\n\n"
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
            return f"Ошибка при получении результатов анализа: {analysis_result.get('error', 'Неизвестная ошибка')}"
    else:
        return (
            f"Ошибка при проверке ссылки: {result.get('error', 'Неизвестная ошибка')}"
        )


@router.message(CommandStart())
async def command_start_handler(message: Message):
    await message.answer(
        f"👋 Приветствую, {message.from_user.full_name}! Отправьте ссылку для проверки."
    )


@router.message(F.text.regexp(r"(http[s]?://)?[^\s]+"))
async def handle_link(message: Message):
    link = message.text
    if not link.startswith("http://") and not link.startswith("https://"):
        link = "http://" + link
    result = scan_url(link)
    await message.answer(result, parse_mode="HTML")
