"""Entry point — run with: python -m cryptobot"""

import asyncio
import logging

from aiogram import Bot

from .bot import create_dispatcher, set_commands
from .config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


async def main() -> None:
    bot = Bot(token=settings.bot_token)
    dp = create_dispatcher()

    await set_commands(bot)
    logger = logging.getLogger(__name__)
    logger.info("CipherX bot starting…")

    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
