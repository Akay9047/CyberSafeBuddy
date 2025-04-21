import logging
import requests
import csv
import os
import re
import random
from bs4 import BeautifulSoup
from telegram import Update, InputTextMessageContent, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters, CallbackQueryHandler, ConversationHandler

# ----------------- CONFIG -----------------
BOT_TOKEN = '7620469030:AAFZ1tET4LiKBZOvdoL9tnmqfVbxo5TF5P0'
VIRUSTOTAL_API_KEY = 'e030dd65b186e3e9b654855622136d25883defda1cf6a590d4eb035db341b4b7'
ADMIN_CHAT_ID = 'YOUR_ADMIN_CHAT_ID'  # Optional: put your Telegram user ID here

CSV_LOG_FILE = 'link_logs.csv'
PHISHING_KEYWORDS = ['login', 'verify', 'banking', 'reset', 'password', 'paypal', 'account', 'secure', 'update']

CYBER_TIPS = [
    "✅ Enable 2FA wherever possible.",
    "🔒 Use strong, unique passwords.",
    "🚫 Never click on suspicious links.",
    "🧠 Stay updated on latest cyber scams.",
    "📵 Avoid using public Wi-Fi for banking.",
    "🤖 Use antivirus & keep software updated."
]

# ----------------- LOGGING -----------------
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# ----------------- FUNCTIONS -----------------

def log_to_csv(user, text, risk_level):
    file_exists = os.path.isfile(CSV_LOG_FILE)
    with open(CSV_LOG_FILE, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(['User', 'Message', 'Risk Level'])
        writer.writerow([user, text, risk_level])

def detect_phishing_keywords(text):
    found = [kw for kw in PHISHING_KEYWORDS if kw.lower() in text.lower()]
    return found

def get_url_preview(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else "No Title Found"
        return title
    except Exception:
        return "Could not fetch preview."

def check_virustotal(url):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    params = {'url': url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
    if response.status_code == 200:
        scan_id = response.json()['data']['id']
        report = requests.get(f'https://www.virustotal.com/api/v3/analyses/{scan_id}', headers=headers)
        if report.status_code == 200:
            results = report.json()
            stats = results['data']['attributes']['stats']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            return malicious, suspicious
    return None, None

# ----------------- HANDLERS -----------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome to CyberSafeBuddy!\n\n"
        "Send me any link and I'll check if it's safe.\n\n"
        "Use /help to view commands."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📖 *Commands:*\n"
        "/start - Start bot\n"
        "/help - Show commands\n"
        "/tips - Get cyber safety tip\n"
        "/feedback - Share your feedback\n"
        "/about - About CyberSafeBuddy",
        parse_mode='Markdown'
    )

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *CyberSafeBuddy v2.0*\n"
        "Detects scam links, phishing keywords, and promotes digital safety.",
        parse_mode='Markdown'
    )

async def tips(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(random.choice(CYBER_TIPS))

async def feedback_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📝 Please type your feedback below:")
    return 1

async def feedback_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user.username
    feedback = update.message.text
    with open("feedback_log.csv", "a") as f:
        f.write(f"{user},{feedback}\n")
    await update.message.reply_text("✅ Thank you for your feedback!")
    return ConversationHandler.END

async def cancel_feedback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Feedback cancelled.")
    return ConversationHandler.END

async def scan_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message.text
    urls = re.findall(r'(https?://\S+)', message)
    if not urls:
        await update.message.reply_text("❗ Please send a valid link.")
        return

    for url in urls:
        await update.message.reply_text(f"🔍 Scanning: {url}")
        title = get_url_preview(url)
        malicious, suspicious = check_virustotal(url)
        keywords = detect_phishing_keywords(url)

        response = f"🌐 *URL Preview:* {title}\n"
        if malicious is not None:
            response += f"🦠 *Malicious:* {malicious}\n⚠️ *Suspicious:* {suspicious}\n"
        else:
            response += "❓ Unable to get VirusTotal result.\n"

        if keywords:
            response += f"🔑 *Phishing Keywords Found:* {', '.join(keywords)}\n"

        if malicious and malicious > 0:
            log_to_csv(update.message.from_user.username, url, "HIGH")
            await update.message.reply_text(response, parse_mode='Markdown')
            if ADMIN_CHAT_ID:
                await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=f"🚨 High-Risk Link Detected from @{update.message.from_user.username}:\n{url}")
        else:
            log_to_csv(update.message.from_user.username, url, "LOW")
            await update.message.reply_text(response, parse_mode='Markdown')

# ----------------- MAIN -----------------

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("tips", tips))
    
    feedback_conv = ConversationHandler(
        entry_points=[CommandHandler("feedback", feedback_start)],
        states={1: [MessageHandler(filters.TEXT & ~filters.COMMAND, feedback_received)]},
        fallbacks=[CommandHandler("cancel", cancel_feedback)]
    )
    app.add_handler(feedback_conv)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_link))

    app.run_polling()

if __name__ == '__main__':
    main()
