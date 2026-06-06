"""CipherX Bot — main handlers."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

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
from .data_store import (
    ban_user,
    get_activity,
    get_bans,
    get_stats,
    get_users,
    is_banned,
    record_operation,
    register_user,
    unban_user,
)

logger = logging.getLogger(__name__)
router = Router()


# ── Ban middleware ─────────────────────────────────────────────────────────────

@router.message.outer_middleware()
async def ban_check(handler, event: types.Message, data):
    uid = event.from_user.id if event.from_user else None
    if uid and is_banned(uid):
        if event.text and event.text.startswith("/start"):
            await event.answer("🚫 You have been blocked from using this bot.")
        return  # silently ignore
    return await handler(event, data)


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
    register_user(message.from_user.id, message.from_user.username, message.from_user.first_name)
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


# ── Admin commands ────────────────────────────────────────────────────────────

def _is_admin(user_id: int) -> bool:
    return user_id in settings.admin_ids


@router.message(Command("stats"))
async def cmd_stats(message: types.Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    stats = get_stats()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_data = stats["daily"].get(today, {"operations": 0, "users": []})
    bans = get_bans()

    # Last 7 days
    now = datetime.now(timezone.utc)
    week_lines: list[str] = []
    for i in range(7):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        d = stats["daily"].get(day, {"operations": 0, "users": []})
        week_lines.append(f"  {day}: {d['operations']} ops, {len(d['users'])} users")

    text = (
        f"📊 <b>CipherX Stats</b>\n\n"
        f"🔢 Total operations: <b>{stats['total_operations']}</b>\n"
        f"👥 Unique users: <b>{len(stats['unique_users'])}</b>\n"
        f"🚫 Banned users: <b>{len(bans)}</b>\n\n"
        f"📅 <b>Today ({today})</b>\n"
        f"  Operations: {today_data['operations']}\n"
        f"  Active users: {len(today_data['users'])}\n\n"
        f"📆 <b>Last 7 days</b>\n" + "\n".join(week_lines)
    )
    await message.answer(text, parse_mode="HTML")


@router.message(Command("users"))
async def cmd_users(message: types.Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    users = get_users()
    if not users:
        await message.answer("👥 No users yet.")
        return

    # Sort by last_seen descending
    sorted_users = sorted(users.items(), key=lambda x: x[1].get("last_seen", ""), reverse=True)
    lines: list[str] = ["👥 <b>Recent Users</b>\n"]
    for uid, info in sorted_users[:20]:
        name = info.get("first_name") or info.get("username") or uid
        uname = f"@{info['username']}" if info.get("username") else ""
        ops = info.get("operations", 0)
        lines.append(f"• <b>{name}</b> {uname} — {ops} ops (ID: <code>{uid}</code>)")

    await message.answer("\n".join(lines), parse_mode="HTML")


@router.message(Command("history"))
async def cmd_history(message: types.Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    activity = get_activity()
    if not activity:
        await message.answer("📜 No activity yet.")
        return

    lines: list[str] = ["📜 <b>Recent Activity</b>\n"]
    for entry in activity[:20]:
        icon = "✅" if entry["success"] else "❌"
        ts = entry.get("ts", "?")[:19]
        lines.append(f"{icon} <code>{entry['user_id']}</code> — {entry['op']} ({entry['method']}) — {ts}")

    await message.answer("\n".join(lines), parse_mode="HTML")


@router.message(Command("ban"))
async def cmd_ban(message: types.Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Usage: /ban <user_id>")
        return
    try:
        target = int(parts[1])
    except ValueError:
        await message.answer("❌ Invalid user ID.")
        return
    if target in settings.admin_ids:
        await message.answer("❌ Cannot ban an admin.")
        return
    if ban_user(target):
        await message.answer(f"🚫 User <code>{target}</code> banned.", parse_mode="HTML")
    else:
        await message.answer(f"⚠️ User <code>{target}</code> is already banned.", parse_mode="HTML")


@router.message(Command("unban"))
async def cmd_unban(message: types.Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Usage: /unban <user_id>")
        return
    try:
        target = int(parts[1])
    except ValueError:
        await message.answer("❌ Invalid user ID.")
        return
    if unban_user(target):
        await message.answer(f"✅ User <code>{target}</code> unbanned.", parse_mode="HTML")
    else:
        await message.answer(f"⚠️ User <code>{target}</code> is not banned.", parse_mode="HTML")


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
            record_operation(uid, "file_encrypt", "aes256", False)
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
        record_operation(uid, "file_encrypt", "aes256", True)

    else:
        # Read encrypted file, decrypt
        with open(sess.temp_file, "r") as f:
            payload = f.read()

        data, err = file_decrypt(payload, password)
        if err:
            record_operation(uid, "file_decrypt", "aes256", False)
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
        record_operation(uid, "file_decrypt", "aes256", True)

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
            record_operation(uid, "hash", sess.method, True)
            await message.answer(
                with_footer(format_hash_result(hr.algorithm, hr.hex_digest)),
                parse_mode="HTML",
            )
        else:
            record_operation(uid, "hash", sess.method, False)
            await message.answer(hr.error)
        clear_session(uid)
        await state.clear()
        return

    # ── HMAC ──────────────────────────────────────────────────────────────────
    if sess.action == "hmac_text":
        result = hmac_text(text, sess.password, sess.method)
        if result.success:
            record_operation(uid, "hmac", sess.method, True)
            await message.answer(
                with_footer(f"🔐 <b>HMAC-{sess.method.upper()}</b>\n\n<code>{result.data}</code>"),
                parse_mode="HTML",
            )
        else:
            record_operation(uid, "hmac", sess.method, False)
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
    uid = message.from_user.id
    if result is None:
        await message.answer("❌ Unknown method.")
        return
    if not result.success:
        record_operation(uid, verb.lower(), method, False)
        await message.answer(result.error)
        return

    data = truncate(result.data)
    record_operation(uid, verb.lower(), method, True)
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
    from aiogram.types import BotCommandScopeChat, BotCommandScopeDefault

    commands = [
        BotCommand(command="start", description="🚀 Start the bot"),
        BotCommand(command="help", description="📖 How to use"),
        BotCommand(command="cancel", description="❌ Cancel current operation"),
    ]
    await bot.set_my_commands(commands, scope=BotCommandScopeDefault())

    # Admin-only commands
    admin_commands = commands + [
        BotCommand(command="stats", description="📊 Bot statistics"),
        BotCommand(command="users", description="👥 Recent users"),
        BotCommand(command="history", description="📜 Recent activity"),
        BotCommand(command="ban", description="🚫 Ban a user"),
        BotCommand(command="unban", description="✅ Unban a user"),
    ]
    for admin_id in settings.admin_ids:
        try:
            await bot.set_my_commands(
                admin_commands,
                scope=BotCommandScopeChat(chat_id=admin_id),
            )
        except Exception as e:
            logger.warning(f"Failed to set admin commands for {admin_id}: {e}")


def create_dispatcher() -> Dispatcher:
    dp = Dispatcher()
    dp.include_router(router)
    return dp
