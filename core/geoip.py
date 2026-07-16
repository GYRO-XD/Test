"""
IP geolocation resolver for GYRO Honeypot.
Uses ip-api.com (free) with caching to avoid rate limits.
"""

import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Optional, Dict


class GeoIPResolver:
    def __init__(self, provider_url: str, enabled: bool = True, cache_size: int = 1000, cache_ttl: int = 86400):
        """
        Initialize the GeoIP resolver.
        
        Args:
            provider_url: URL template with {ip} placeholder
            enabled: Whether geoip is enabled
            cache_size: Maximum number of entries in cache (ignored, kept for compatibility)
            cache_ttl: Cache TTL in seconds
        """
        self.provider_url = provider_url
        self.enabled = enabled
        self.cache = {}
        self.cache_ttl = timedelta(seconds=cache_ttl)
        self.max_cache_size = cache_size
        self._lock = asyncio.Lock()

    async def resolve(self, ip: str) -> Dict[str, str]:
        """
        Resolve IP to geolocation data.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            Dictionary with country, city, isp fields
        """
        if not self.enabled:
            return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

        # Check cache first
        async with self._lock:
            if ip in self.cache:
                cached_data, timestamp = self.cache[ip]
                if datetime.now() - timestamp < self.cache_ttl:
                    return cached_data

        try:
            url = self.provider_url.format(ip=ip)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Parse response
                        geo_data = {
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "region": data.get("regionName", "Unknown"),
                            "status": data.get("status", "Unknown")
                        }
                        
                        # Cache the result
                        async with self._lock:
                            # If cache is too large, remove oldest entry
                            if len(self.cache) >= self.max_cache_size:
                                oldest_key = next(iter(self.cache))
                                del self.cache[oldest_key]
                            self.cache[ip] = (geo_data, datetime.now())
                        
                        return geo_data
                    else:
                        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
        except Exception as e:
            print(f"[GeoIP Error] Failed to resolve {ip}: {e}")
            return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    async def resolve_batch(self, ips: list) -> Dict[str, Dict[str, str]]:
        """
        Resolve multiple IPs in batch.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dictionary mapping IP to geolocation data
        """
        results = {}
        for ip in ips:
            results[ip] = await self.resolve(ip)
        return results

    def clear_cache(self):
        """Clear the geolocation cache."""
        self.cache.clear()

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "size": len(self.cache),
            "max_size": self.max_cache_size,
            "entries": len(self.cache)
        }
