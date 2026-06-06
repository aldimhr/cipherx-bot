"""Telegram Stars donation support."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from aiogram import Bot, types
from aiogram.types import LabeledPrice

from .data_store import _read_json, _write_json
import os

logger = logging.getLogger(__name__)

DONATION_AMOUNTS = [
    {"label": "⭐ 25 Stars", "amount": 25},
    {"label": "⭐ 50 Stars", "amount": 50},
    {"label": "⭐ 100 Stars", "amount": 100},
    {"label": "⭐ 250 Stars", "amount": 250},
    {"label": "⭐ 500 Stars", "amount": 500},
]

DONATE_TEXT = (
    "⭐ <b>Support CipherX with Telegram Stars!</b>\n\n"
    "Your donation helps keep this bot running and ad-free.\n"
    "Choose an amount below, or use <code>/donate &lt;amount&gt;</code> for a custom amount."
)


def donation_keyboard() -> types.InlineKeyboardMarkup:
    buttons = [
        [types.InlineKeyboardButton(text=d["label"], callback_data=f"donate:{d['amount']}")]
        for d in DONATION_AMOUNTS
    ]
    buttons.append([types.InlineKeyboardButton(text="💝 Custom Amount", callback_data="donate:custom")])
    return types.InlineKeyboardMarkup(inline_keyboard=buttons)


async def send_invoice(bot: Bot, chat_id: int, amount: int, reply_to: int | None = None) -> bool:
    """Send a Stars invoice. Returns True on success."""
    try:
        await bot.send_invoice(
            chat_id=chat_id,
            title=f"{amount} Stars Donation",
            description=f"Support CipherX Bot with {amount} Telegram Stars. Thank you! 💙",
            payload=f"donate:{amount}:{int(datetime.now(timezone.utc).timestamp())}",
            provider_token="",  # empty for Telegram Stars
            currency="XTR",
            prices=[LabeledPrice(label=f"{amount} Stars", amount=amount)],
            reply_to_message_id=reply_to,
        )
        return True
    except Exception as e:
        logger.error(f"Invoice failed: {e}")
        return False


async def handle_donate_callback(callback: types.CallbackQuery, bot: Bot) -> None:
    """Handle inline keyboard button press for donation."""
    data = callback.data or ""
    amount_str = data.split(":")[1]

    if amount_str == "custom":
        await callback.answer("Type /donate <amount> for a custom amount", show_alert=True)
        return

    try:
        amount = int(amount_str)
    except ValueError:
        await callback.answer("Invalid amount")
        return

    await callback.answer()
    ok = await send_invoice(bot, callback.message.chat.id, amount, callback.message.message_id)
    if not ok:
        await callback.message.answer("❌ Failed to create invoice. Please try again.")


def log_donation(user_id: int, amount: int) -> None:
    """Log a successful donation."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "donations.json")
    donations = _read_json(path, [])
    donations.insert(0, {
        "user_id": user_id,
        "amount": amount,
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    if len(donations) > 200:
        donations = donations[:200]
    _write_json(path, donations)


def get_donations() -> list[dict]:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "donations.json")
    return _read_json(path, [])
