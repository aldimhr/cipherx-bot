"""Reply and inline keyboards."""

from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)


# ── Main reply keyboard ──────────────────────────────────────────────────────

main_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="🔐 Encrypt Text"), KeyboardButton(text="🔓 Decrypt Text")],
        [KeyboardButton(text="#️⃣ Hash Text"), KeyboardButton(text="🔑 Generate Password")],
        [KeyboardButton(text="📁 Encrypt File"), KeyboardButton(text="📂 Decrypt File")],
        [KeyboardButton(text="ℹ️ Help"), KeyboardButton(text="📢 Channel")],
    ],
    resize_keyboard=True,
    input_field_placeholder="Choose an action…",
)


# ── Method selection keyboards ────────────────────────────────────────────────

def encrypt_method_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="AES-256", callback_data="enc:aes"),
         InlineKeyboardButton(text="Fernet", callback_data="enc:fernet")],
        [InlineKeyboardButton(text="Base64", callback_data="enc:base64"),
         InlineKeyboardButton(text="ROT13", callback_data="enc:rot13")],
        [InlineKeyboardButton(text="Caesar", callback_data="enc:caesar")],
    ])


def decrypt_method_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="AES-256", callback_data="dec:aes"),
         InlineKeyboardButton(text="Fernet", callback_data="dec:fernet")],
        [InlineKeyboardButton(text="Base64", callback_data="dec:base64"),
         InlineKeyboardButton(text="ROT13", callback_data="dec:rot13")],
        [InlineKeyboardButton(text="Caesar", callback_data="dec:caesar")],
    ])


def hash_algorithm_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="SHA-256", callback_data="hash:sha256"),
         InlineKeyboardButton(text="SHA-512", callback_data="hash:sha512")],
        [InlineKeyboardButton(text="MD5", callback_data="hash:md5"),
         InlineKeyboardButton(text="SHA-1", callback_data="hash:sha1")],
        [InlineKeyboardButton(text="SHA3-256", callback_data="hash:sha3_256"),
         InlineKeyboardButton(text="BLAKE2b", callback_data="hash:blake2b")],
        [InlineKeyboardButton(text="HMAC-SHA256", callback_data="hmac:sha256")],
    ])


def password_length_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="16", callback_data="gen:16"),
         InlineKeyboardButton(text="24", callback_data="gen:24"),
         InlineKeyboardButton(text="32", callback_data="gen:32")],
        [InlineKeyboardButton(text="48", callback_data="gen:48"),
         InlineKeyboardButton(text="64", callback_data="gen:64"),
         InlineKeyboardButton(text="128", callback_data="gen:128")],
    ])
