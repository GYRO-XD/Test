"""
Telegram notification handler for GYRO Honeypot.
"""

import aiohttp
import asyncio
from datetime import datetime


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str, enabled: bool = True, 
                 rate_limit_seconds: int = 30):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = enabled and bot_token and chat_id
        self.rate_limit_seconds = rate_limit_seconds
        self._last_alert = {}
        self._alert_lock = asyncio.Lock()

    async def send_alert(self, ip: str, port: int, service: str, geo: dict, extra: str = ""):
        if not self.enabled:
            return

        key = f"{ip}:{port}"
        async with self._alert_lock:
            now = datetime.now()
            if key in self._last_alert:
                last_time = self._last_alert[key]
                if (now - last_time).total_seconds() < self.rate_limit_seconds:
                    return
            self._last_alert[key] = now

        location = geo.get("location", f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
        isp = geo.get("isp", "Unknown")
        
        message = (
            f"🔔 Honeypot Alert\n\n"
            f"🌐 IP: {ip}\n"
            f"📍 Location: {location}\n"
            f"🏢 ISP: {isp}\n"
            f"🔌 Service: {service} (Port {port})\n"
            f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        
        if extra:
            if len(extra) > 500:
                extra = extra[:500] + "..."
            message += f"\n📝 Data:\n{extra}"

        await self._send_message(message)

    async def send_raw_alert(self, message: str):
        if not self.enabled:
            return
        
        if len(message) > 4096:
            message = message[:4093] + "..."
        
        await self._send_message(message)

    async def _send_message(self, message: str):
        if not self.enabled:
            return

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=10) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        print(f"[Telegram Error] {response.status}: {error_text}")
        except Exception as e:
            print(f"[Telegram Error] Failed to send message: {e}")
