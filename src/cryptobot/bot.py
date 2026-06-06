"""CipherX Bot — main handlers."""

from __future__ import annotations

import logging

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BotCommand

from .config import settings
from .crypto import (
    aes_decrypt,
    aes_encrypt,
    b64_decode,
    b64_encode,
    caesar_decrypt,
    caesar_encrypt,
    fernet_decrypt,
    fernet_encrypt,
    fernet_generate_key,
    file_decrypt,
    file_encrypt,
    generate_password,
    hash_text,
    hmac_text,
    rot13,
)
from .keyboards import (
    decrypt_method_keyboard,
    encrypt_method_keyboard,
    hash_algorithm_keyboard,
    main_keyboard,
    password_length_keyboard,
)
from .utils import (
    UserSession,
    clear_session,
    code_block,
    format_hash_result,
    get_session,
    set_session,
    temp_path,
    truncate,
    with_footer,
)

logger = logging.getLogger(__name__)
router = Router()


# ── States ────────────────────────────────────────────────────────────────────

class CryptoState(StatesGroup):
    waiting_text = State()
    waiting_password = State()
    waiting_caesar_shift = State()
    waiting_hmac_key = State()
    waiting_file = State()
    waiting_file_password = State()


# ── Welcome & Help ────────────────────────────────────────────────────────────

WELCOME = """🔐 <b>CipherX Bot</b>

Your all-in-one encryption & decryption toolkit!

<b>Features:</b>
• 🔐 AES-256, Fernet, Base64, ROT13, Caesar encryption
• 🔓 Decrypt any supported format
• #️⃣ Hash with SHA-256, SHA-512, MD5, SHA-1, BLAKE2, SHA3
• 🔑 Cryptographically secure password generator
• 📁📂 File encryption & decryption

Choose an action below to get started 👇"""

HELP_TEXT = """ℹ️ <b>How to use CipherX</b>

<b>🔐 Encrypt Text</b>
Choose a method → send your text → enter a password (if needed).

<b>🔓 Decrypt Text</b>
Choose a method → send the encrypted text → enter the password.

<b>#️⃣ Hash Text</b>
Choose an algorithm → send your text → get the hash instantly.

<b>🔑 Generate Password</b>
Pick a length → get a cryptographically secure password.

<b>📁 Encrypt File</b>
Upload a file → enter a password → get the encrypted file back.

<b>📂 Decrypt File</b>
Upload an encrypted file → enter the password → get the original.

<b>Supported Methods:</b>
• <b>AES-256</b> — military-grade symmetric encryption (password required)
• <b>Fernet</b> — authenticated symmetric encryption (key or password)
• <b>Base64</b> — encoding (not encryption — for data transport)
• <b>ROT13</b> — simple letter substitution (fun, not secure)
• <b>Caesar</b> — classic shift cipher (customizable shift value)

⚠️ <b>Security Note:</b> All processing is done server-side. No text or files are stored after the response is sent."""


@router.message(CommandStart())
async def cmd_start(message: types.Message) -> None:
    clear_session(message.from_user.id)
    await message.answer(with_footer(WELCOME), reply_markup=main_keyboard, parse_mode="HTML")


@router.message(Command("help"))
async def cmd_help(message: types.Message) -> None:
    await message.answer(with_footer(HELP_TEXT), reply_markup=main_keyboard, parse_mode="HTML")


@router.message(F.text == "ℹ️ Help")
async def btn_help(message: types.Message) -> None:
    await cmd_help(message)


@router.message(F.text == "📢 Channel")
async def btn_channel(message: types.Message) -> None:
    await message.answer(
        "📢 Join <b>@x0projects</b> for updates & new bots!\n\nhttps://t.me/x0projects",
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


# ── Encrypt Text Flow ────────────────────────────────────────────────────────

@router.message(F.text == "🔐 Encrypt Text")
async def btn_encrypt(message: types.Message, state: FSMContext) -> None:
    clear_session(message.from_user.id)
    set_session(message.from_user.id, UserSession(action="encrypt_text"))
    await state.set_state(CryptoState.waiting_text)
    await message.answer(
        "🔐 <b>Choose encryption method:</b>",
        reply_markup=encrypt_method_keyboard(),
        parse_mode="HTML",
    )


@router.callback_query(F.data.startswith("enc:"))
async def cb_encrypt_method(callback: types.CallbackQuery, state: FSMContext) -> None:
    method = callback.data.split(":")[1]
    uid = callback.from_user.id
    sess = get_session(uid)
    if not sess or sess.action != "encrypt_text":
        await callback.answer("Session expired. Try again.", show_alert=True)
        return

    sess.method = method
    set_session(uid, sess)
    await callback.answer()

    if method == "caesar":
        await state.set_state(CryptoState.waiting_caesar_shift)
        await callback.message.edit_text(
            "🔢 Enter the <b>shift value</b> (1-25, default=3):",
            parse_mode="HTML",
        )
        return

    await state.set_state(CryptoState.waiting_text)
    prompts = {
        "aes": "🔐 <b>AES-256 Encryption</b>\n\nSend the text you want to encrypt:",
        "fernet": "🔐 <b>Fernet Encryption</b>\n\nSend the text you want to encrypt:",
        "base64": "🔐 <b>Base64 Encoding</b>\n\nSend the text you want to encode:",
        "rot13": "🔐 <b>ROT13</b>\n\nSend the text you want to transform:",
    }
    await callback.message.edit_text(prompts.get(method, "Send your text:"), parse_mode="HTML")


@router.message(CryptoState.waiting_caesar_shift)
async def process_caesar_shift(message: types.Message, state: FSMContext) -> None:
    uid = message.from_user.id
    sess = get_session(uid)
    if not sess:
        await state.clear()
        return

    try:
        shift = int(message.text.strip())
        if not 1 <= shift <= 25:
            raise ValueError
    except ValueError:
        shift = 3

    sess.shift = shift
    sess.step = "input"
    set_session(uid, sess)
    await state.set_state(CryptoState.waiting_text)
    await message.answer(f"🔢 Shift set to <b>{shift}</b>. Now send your text:", parse_mode="HTML")


# ── Decrypt Text Flow ────────────────────────────────────────────────────────

@router.message(F.text == "🔓 Decrypt Text")
async def btn_decrypt(message: types.Message, state: FSMContext) -> None:
    clear_session(message.from_user.id)
    set_session(message.from_user.id, UserSession(action="decrypt_text"))
    await state.set_state(CryptoState.waiting_text)
    await message.answer(
        "🔓 <b>Choose decryption method:</b>",
        reply_markup=decrypt_method_keyboard(),
        parse_mode="HTML",
    )


@router.callback_query(F.data.startswith("dec:"))
async def cb_decrypt_method(callback: types.CallbackQuery, state: FSMContext) -> None:
    method = callback.data.split(":")[1]
    uid = callback.from_user.id
    sess = get_session(uid)
    if not sess or sess.action != "decrypt_text":
        await callback.answer("Session expired. Try again.", show_alert=True)
        return

    sess.method = method
    set_session(uid, sess)
    await callback.answer()

    if method == "caesar":
        await state.set_state(CryptoState.waiting_caesar_shift)
        await callback.message.edit_text(
            "🔢 Enter the <b>shift value</b> (1-25, default=3):",
            parse_mode="HTML",
        )
        return

    await state.set_state(CryptoState.waiting_text)
    prompts = {
        "aes": "🔓 <b>AES-256 Decryption</b>\n\nSend the encrypted text:",
        "fernet": "🔓 <b>Fernet Decryption</b>\n\nSend the Fernet token:",
        "base64": "🔓 <b>Base64 Decoding</b>\n\nSend the encoded text:",
        "rot13": "🔓 <b>ROT13</b>\n\nSend the ROT13 text:",
    }
    await callback.message.edit_text(prompts.get(method, "Send the encrypted text:"), parse_mode="HTML")


# ── Hash Text Flow ───────────────────────────────────────────────────────────

@router.message(F.text == "#️⃣ Hash Text")
async def btn_hash(message: types.Message, state: FSMContext) -> None:
    clear_session(message.from_user.id)
    set_session(message.from_user.id, UserSession(action="hash_text"))
    await message.answer(
        "#️⃣ <b>Choose hash algorithm:</b>",
        reply_markup=hash_algorithm_keyboard(),
        parse_mode="HTML",
    )


@router.callback_query(F.data.startswith("hash:"))
async def cb_hash_algo(callback: types.CallbackQuery, state: FSMContext) -> None:
    algo = callback.data.split(":")[1]
    uid = callback.from_user.id
    sess = get_session(uid)
    if not sess or sess.action != "hash_text":
        await callback.answer("Session expired.", show_alert=True)
        return

    sess.method = algo
    set_session(uid, sess)
    await callback.answer()
    await state.set_state(CryptoState.waiting_text)
    await callback.message.edit_text(
        f"#️⃣ <b>{algo.upper()}</b>\n\nSend the text to hash:",
        parse_mode="HTML",
    )


@router.callback_query(F.data.startswith("hmac:"))
async def cb_hmac_algo(callback: types.CallbackQuery, state: FSMContext) -> None:
    algo = callback.data.split(":")[1]
    uid = callback.from_user.id
    sess = get_session(uid)
    if not sess or sess.action != "hash_text":
        await callback.answer("Session expired.", show_alert=True)
        return

    sess.action = "hmac_text"
    sess.method = algo
    set_session(uid, sess)
    await callback.answer()
    await state.set_state(CryptoState.waiting_hmac_key)
    await callback.message.edit_text(
        f"🔐 <b>HMAC-{algo.upper()}</b>\n\nSend the HMAC key first:",
        parse_mode="HTML",
    )


@router.message(CryptoState.waiting_hmac_key)
async def process_hmac_key(message: types.Message, state: FSMContext) -> None:
    uid = message.from_user.id
    sess = get_session(uid)
    if not sess or sess.action != "hmac_text":
        await state.clear()
        return

    sess.password = message.text.strip()
    sess.step = "input"
    set_session(uid, sess)
    await state.set_state(CryptoState.waiting_text)
    await message.answer("📝 Now send the text to sign:")


# ── Generate Password Flow ───────────────────────────────────────────────────

@router.message(F.text == "🔑 Generate Password")
async def btn_generate(message: types.Message) -> None:
    await message.answer(
        "🔑 <b>Choose password length:</b>",
        reply_markup=password_length_keyboard(),
        parse_mode="HTML",
    )


@router.callback_query(F.data.startswith("gen:"))
async def cb_generate(callback: types.CallbackQuery) -> None:
    length = int(callback.data.split(":")[1])
    pw = generate_password(length)
    await callback.answer()
    await callback.message.edit_text(
        f"🔑 <b>Generated Password ({length} chars)</b>\n\n"
        f"<code>{pw}</code>\n\n"
        f"_Tap to copy_",
        parse_mode="HTML",
    )


# ── File Encrypt/Decrypt ─────────────────────────────────────────────────────

@router.message(F.text == "📁 Encrypt File")
async def btn_file_encrypt(message: types.Message, state: FSMContext) -> None:
    clear_session(message.from_user.id)
    set_session(message.from_user.id, UserSession(action="encrypt_file"))
    await state.set_state(CryptoState.waiting_file)
    await message.answer(
        "📁 <b>File Encryption</b>\n\nUpload the file you want to encrypt:",
        parse_mode="HTML",
    )


@router.message(F.text == "📂 Decrypt File")
async def btn_file_decrypt(message: types.Message, state: FSMContext) -> None:
    clear_session(message.from_user.id)
    set_session(message.from_user.id, UserSession(action="decrypt_file"))
    await state.set_state(CryptoState.waiting_file)
    await message.answer(
        "📂 <b>File Decryption</b>\n\nUpload the encrypted file:",
        parse_mode="HTML",
    )


@router.message(CryptoState.waiting_file, F.document)
async def process_file_upload(message: types.Message, state: FSMContext) -> None:
    uid = message.from_user.id
    sess = get_session(uid)
    if not sess or sess.action not in ("encrypt_file", "decrypt_file"):
        await state.clear()
        return

    # Check file size (20 MB limit)
    if message.document.file_size and message.document.file_size > 20 * 1024 * 1024:
        await message.answer("❌ File too large. Maximum size is 20 MB.")
        return

    # Download file
    bot: Bot = message.bot
    file = await bot.get_file(message.document.file_id)
    suffix = ".enc" if sess.action == "encrypt_file" else ".bin"
    local_path = temp_path(suffix=suffix)

    await bot.download_file(file.file_path, local_path)

    sess.temp_file = local_path
    sess.data["filename"] = message.document.file_name or "file"
    sess.step = "password"
    set_session(uid, sess)
    await state.set_state(CryptoState.waiting_file_password)

    action_word = "encrypt" if sess.action == "encrypt_file" else "decrypt"
    await message.answer(f"✅ File received. Enter the password to {action_word}:")


@router.message(CryptoState.waiting_file_password)
async def process_file_password(message: types.Message, state: FSMContext) -> None:
    uid = message.from_user.id
    sess = get_session(uid)
    if not sess or sess.action not in ("encrypt_file", "decrypt_file"):
        await state.clear()
        return

    password = message.text.strip()
    import os

    if sess.action == "encrypt_file":
        # Read, encrypt, save
        with open(sess.temp_file, "rb") as f:
            data = f.read()

        result = file_encrypt(data, password)
        if not result.success:
            await message.answer(result.error)
            clear_session(uid)
            await state.clear()
            return

        # Save encrypted file
        enc_path = temp_path(suffix=".enc")
        with open(enc_path, "w") as f:
            f.write(result.data)

        from aiogram.types import FSInputFile
        await message.answer_document(
            FSInputFile(enc_path, filename=sess.data["filename"] + ".enc"),
            caption=with_footer("✅ File encrypted with AES-256-GCM"),
        )
        os.remove(enc_path)

    else:
        # Read encrypted file, decrypt
        with open(sess.temp_file, "r") as f:
            payload = f.read()

        data, err = file_decrypt(payload, password)
        if err:
            await message.answer(err)
            clear_session(uid)
            await state.clear()
            return

        # Save decrypted file
        dec_path = temp_path(suffix=".dec")
        with open(dec_path, "wb") as f:
            f.write(data)

        fname = sess.data["filename"]
        if fname.endswith(".enc"):
            fname = fname[:-4]

        from aiogram.types import FSInputFile
        await message.answer_document(
            FSInputFile(dec_path, filename=fname),
            caption=with_footer("✅ File decrypted successfully"),
        )
        os.remove(dec_path)

    clear_session(uid)
    await state.clear()


# ── Text input handler (dispatches based on session) ─────────────────────────

@router.message(CryptoState.waiting_text, F.text)
async def process_text_input(message: types.Message, state: FSMContext) -> None:
    uid = message.from_user.id
    sess = get_session(uid)
    if not sess:
        await state.clear()
        return

    text = message.text.strip()

    # ── Encrypt ───────────────────────────────────────────────────────────────
    if sess.action == "encrypt_text":
        if sess.method in ("aes", "fernet"):
            # Need password next
            sess.data["plaintext"] = text
            sess.step = "password"
            set_session(uid, sess)
            await state.set_state(CryptoState.waiting_password)
            await message.answer("🔑 Enter the password (or key):")
            return

        result = _encrypt_dispatch(sess.method, text, sess.shift)
        await _send_result(message, result, sess.method, "Encrypted")
        clear_session(uid)
        await state.clear()
        return

    # ── Decrypt ───────────────────────────────────────────────────────────────
    if sess.action == "decrypt_text":
        if sess.method in ("aes", "fernet"):
            sess.data["ciphertext"] = text
            sess.step = "password"
            set_session(uid, sess)
            await state.set_state(CryptoState.waiting_password)
            await message.answer("🔑 Enter the password (or key):")
            return

        result = _decrypt_dispatch(sess.method, text, sess.shift)
        await _send_result(message, result, sess.method, "Decrypted")
        clear_session(uid)
        await state.clear()
        return

    # ── Hash ──────────────────────────────────────────────────────────────────
    if sess.action == "hash_text":
        hr = hash_text(text, sess.method)
        if hasattr(hr, "hex_digest"):
            await message.answer(
                with_footer(format_hash_result(hr.algorithm, hr.hex_digest)),
                parse_mode="HTML",
            )
        else:
            await message.answer(hr.error)
        clear_session(uid)
        await state.clear()
        return

    # ── HMAC ──────────────────────────────────────────────────────────────────
    if sess.action == "hmac_text":
        result = hmac_text(text, sess.password, sess.method)
        if result.success:
            await message.answer(
                with_footer(f"🔐 <b>HMAC-{sess.method.upper()}</b>\n\n<code>{result.data}</code>"),
                parse_mode="HTML",
            )
        else:
            await message.answer(result.error)
        clear_session(uid)
        await state.clear()
        return


@router.message(CryptoState.waiting_password, F.text)
async def process_password_input(message: types.Message, state: FSMContext) -> None:
    uid = message.from_user.id
    sess = get_session(uid)
    if not sess:
        await state.clear()
        return

    password = message.text.strip()

    if sess.action == "encrypt_text":
        result = _encrypt_with_password(sess.method, sess.data.get("plaintext", ""), password)
        await _send_result(message, result, sess.method, "Encrypted")
    elif sess.action == "decrypt_text":
        result = _decrypt_with_password(sess.method, sess.data.get("ciphertext", ""), password)
        await _send_result(message, result, sess.method, "Decrypted")

    clear_session(uid)
    await state.clear()


# ── Dispatch helpers ──────────────────────────────────────────────────────────

def _encrypt_dispatch(method: str, text: str, shift: int = 3):
    if method == "base64":
        return b64_encode(text)
    elif method == "rot13":
        return rot13(text)
    elif method == "caesar":
        return caesar_encrypt(text, shift)
    return None


def _decrypt_dispatch(method: str, text: str, shift: int = 3):
    if method == "base64":
        return b64_decode(text)
    elif method == "rot13":
        return rot13(text)
    elif method == "caesar":
        return caesar_decrypt(text, shift)
    return None


def _encrypt_with_password(method: str, text: str, password: str):
    if method == "aes":
        return aes_encrypt(text, password)
    elif method == "fernet":
        return fernet_encrypt(text, password)
    return None


def _decrypt_with_password(method: str, text: str, password: str):
    if method == "aes":
        return aes_decrypt(text, password)
    elif method == "fernet":
        return fernet_decrypt(text, password)
    return None


async def _send_result(message: types.Message, result, method: str, verb: str) -> None:
    if result is None:
        await message.answer("❌ Unknown method.")
        return
    if not result.success:
        await message.answer(result.error)
        return

    data = truncate(result.data)
    await message.answer(
        with_footer(f"✅ <b>{verb}</b> ({method.upper()})\n\n{code_block(data)}"),
        parse_mode="HTML",
    )


# ── Cancel / reset ───────────────────────────────────────────────────────────

@router.message(Command("cancel"))
async def cmd_cancel(message: types.Message, state: FSMContext) -> None:
    clear_session(message.from_user.id)
    await state.clear()
    await message.answer("✅ Cancelled.", reply_markup=main_keyboard)


# ── Unknown message fallback ─────────────────────────────────────────────────

@router.message()
async def fallback(message: types.Message, state: FSMContext) -> None:
    current = await state.get_state()
    if current:
        return  # In a flow, ignore stray messages
    await message.answer(
        "🤔 I didn't understand that. Use the buttons below or /help for guidance.",
        reply_markup=main_keyboard,
    )


# ── Bot setup ────────────────────────────────────────────────────────────────

async def set_commands(bot: Bot) -> None:
    commands = [
        BotCommand(command="start", description="🚀 Start the bot"),
        BotCommand(command="help", description="📖 How to use"),
        BotCommand(command="cancel", description="❌ Cancel current operation"),
    ]
    await bot.set_my_commands(commands)


def create_dispatcher() -> Dispatcher:
    dp = Dispatcher()
    dp.include_router(router)
    return dp
