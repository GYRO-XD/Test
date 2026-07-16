"""
Telegram notification handler for GYRO Honeypot.
Sends alerts with rate limiting to avoid spam.
"""

import aiohttp
import asyncio
from datetime import datetime, timedelta
from typing import Optional


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str, enabled: bool = True, 
                 rate_limit_seconds: int = 30, include_credentials: bool = True):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = enabled and bot_token and chat_id
        self.rate_limit_seconds = rate_limit_seconds
        self.include_credentials = include_credentials
        self._last_alert = {}
        self._alert_lock = asyncio.Lock()

    async def send_alert(self, ip: str, port: int, service: str, geo: dict, extra: str = ""):
        """Send an alert to Telegram with rate limiting."""
        if not self.enabled:
            return

        # Rate limit check
        key = f"{ip}:{port}"
        async with self._alert_lock:
            now = datetime.now()
            if key in self._last_alert:
                last_time = self._last_alert[key]
                if (now - last_time).total_seconds() < self.rate_limit_seconds:
                    return
            self._last_alert[key] = now

        # Build message
        country = geo.get("country", "Unknown")
        city = geo.get("city", "Unknown")
        isp = geo.get("isp", "Unknown")
        
        message = (
            f"🔔 Honeypot Alert\n\n"
            f"🌐 IP: {ip}\n"
            f"📍 Location: {country}, {city}\n"
            f"🏢 ISP: {isp}\n"
            f"🔌 Service: {service} (Port {port})\n"
            f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        
        if extra:
            # Truncate extra if it's too long
            if len(extra) > 500:
                extra = extra[:500] + "..."
            message += f"\n📝 Data:\n{extra}"

        await self._send_message(message)

    async def send_raw_alert(self, message: str):
        """Send a raw alert message to Telegram."""
        if not self.enabled:
            return
        
        # Truncate if too long
        if len(message) > 4096:
            message = message[:4093] + "..."
        
        await self._send_message(message)

    async def send_credential_alert(self, ip: str, service: str, port: int, 
                                   geo: dict, credentials: dict):
        """Send a special alert for captured credentials."""
        if not self.enabled or not self.include_credentials:
            return

        country = geo.get("country", "Unknown")
        city = geo.get("city", "Unknown")
        isp = geo.get("isp", "Unknown")
        
        # FIXED: Using proper bullet points
        creds_str = "\n".join([f"• {k}: {v}" for k, v in credentials.items()])
        
        message = (
            f"🔐 CREDENTIALS CAPTURED!\n\n"
            f"🌐 IP: {ip}\n"
            f"📍 Location: {country}, {city}\n"
            f"🏢 ISP: {isp}\n"
            f"🔌 Service: {service} (Port {port})\n"
            f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"📝 Credentials:\n{creds_str}"
        )
        
        await self._send_message(message)

    async def _send_message(self, message: str):
        """Send a message to Telegram."""
        if not self.enabled:
            return

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=10) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        print(f"[Telegram Error] {response.status}: {error_text}")
        except Exception as e:
            print(f"[Telegram Error] Failed to send message: {e}")
