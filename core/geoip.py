"""
IP geolocation resolver for GYRO Honeypot.
"""

import asyncio
import aiohttp
from datetime import datetime, timedelta

class GeoIPResolver:
    def __init__(self, provider_url, enabled=True):
        self.provider_url = provider_url
        self.enabled = enabled
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)

    async def resolve(self, ip):
        if not self.enabled:
            return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "location": "Unknown"}
        
        if ip in self.cache:
            data, timestamp = self.cache[ip]
            if datetime.now() - timestamp < self.cache_ttl:
                return data
        
        try:
            url = self.provider_url.format(ip=ip)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        geo_data = {
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "location": f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                        }
                        self.cache[ip] = (geo_data, datetime.now())
                        return geo_data
        except Exception:
            pass
        
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "location": "Unknown"}
