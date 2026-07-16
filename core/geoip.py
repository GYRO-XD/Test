"""
IP geolocation for GYRO Honeypot.
Uses ip-api.com (free tier, no key required, 45 req/min limit).
Caches results per-IP so a repeat attacker doesn't burn your rate limit.
"""

import aiohttp
import asyncio


class GeoIPResolver:
    def __init__(self, provider_url: str, enabled: bool = True):
        self.provider_url = provider_url
        self.enabled = enabled
        self._cache = {}
        self._lock = asyncio.Lock()

    async def resolve(self, ip: str) -> dict:
        if not self.enabled:
            return {"country": "N/A", "city": "N/A", "isp": "N/A"}

        # Skip lookups for local/private addresses, they'll always fail anyway
        if ip.startswith(("127.", "10.", "192.168.")) or ip.startswith("172."):
            return {"country": "Local/Private", "city": "-", "isp": "-"}

        async with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
        try:
            url = self.provider_url.format(ip=ip)
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            result = {
                                "country": data.get("country", "Unknown"),
                                "city": data.get("city", "Unknown"),
                                "isp": data.get("isp", "Unknown"),
                            }
        except (asyncio.TimeoutError, aiohttp.ClientError):
            pass  # geolocation is best-effort; never let it break the honeypot

        async with self._lock:
            self._cache[ip] = result
        return result
