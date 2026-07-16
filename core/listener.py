#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fake service listeners for GYRO Honeypot.
"""

import asyncio
import datetime
import urllib.parse
import re
import json
from pathlib import Path
from typing import Optional, Dict, Any


class HoneypotService:
    def __init__(self, name: str, port: int, banner: str,
                 event_logger, geoip_resolver, notifier, dashboard_state: dict,
                 template_dir: Optional[Path] = None,
                 service_config: Optional[Dict] = None,
                 security_config: Optional[Dict] = None,
                 performance_config: Optional[Dict] = None):
        self.name = name
        self.port = port
        self.banner = banner
        self.logger = event_logger
        self.geoip = geoip_resolver
        self.notifier = notifier
        self.dashboard_state = dashboard_state
        self.template_dir = template_dir or Path("templates")
        self.service_config = service_config or {}
        self.security_config = security_config or {}
        self.performance_config = performance_config or {}
        
        self.connection_counts = {}
        self.banned_ips = {}
        
        self.is_http = self.service_config.get("type") == "http"
        self.template_name = self.service_config.get("template", f"{name.lower()}.html")
        self.login_endpoint = self.service_config.get("login_endpoint", "/login")
        self.success_redirect = self.service_config.get("success_redirect", "/?success=1")
        
        self.template_cache = {}
        self._load_templates()

    def _load_templates(self):
        if not self.template_dir.exists():
            self.template_dir.mkdir(parents=True, exist_ok=True)
            return

        if self.is_http:
            template_path = self.template_dir / self.template_name
            if template_path.exists():
                with open(template_path, 'r', encoding='utf-8') as f:
                    self.template_cache['main'] = f.read()
            else:
                self.template_cache['main'] = self._get_default_template()

    def _get_default_template(self) -> str:
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{self.name} Login</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                input {{ width: 100%; padding: 10px; margin: 10px 0; }}
                button {{ width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }}
            </style>
        </head>
        <body>
            <h2>{self.name} Login</h2>
            <form method="POST" action="{self.login_endpoint}">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """

    def _parse_http_request(self, data: str) -> tuple:
        method = path = headers = body = ""
        try:
            if '\r\n\r\n' in data:
                header_part, body = data.split('\r\n\r\n', 1)
            elif '\n\n' in data:
                header_part, body = data.split('\n\n', 1)
            else:
                header_part = data
                body = ""

            lines = header_part.split('\r\n')
            if lines:
                request_line = lines[0].split(' ')
                if len(request_line) >= 3:
                    method = request_line[0].upper()
                    path = request_line[1]
                    headers = lines[1:] if len(lines) > 1 else []
        except Exception:
            pass
        return method, path, headers, body

    def _extract_credentials(self, body: str, headers: list = None) -> dict:
        credentials = {}
        
        try:
            # Check JSON
            if body.strip().startswith('{') or body.strip().startswith('['):
                try:
                    json_data = json.loads(body)
                    for field in ['username', 'user', 'email', 'login', 'phone', 'phoneNumber']:
                        if field in json_data:
                            credentials['username'] = json_data[field]
                            break
                    for field in ['password', 'pass', 'pwd', 'secret']:
                        if field in json_data:
                            credentials['password'] = json_data[field]
                            break
                    if not credentials:
                        credentials = json_data
                except json.JSONDecodeError:
                    pass
            
            # Check URL-encoded
            if not credentials and ('=' in body or '%' in body):
                try:
                    parsed = urllib.parse.parse_qs(body)
                    username_fields = ['username', 'user', 'email', 'login', 'phone', 'phoneNumber']
                    for field in username_fields:
                        if field in parsed and parsed[field]:
                            credentials['username'] = parsed[field][0]
                            break
                    
                    password_fields = ['password', 'pass', 'pwd', 'secret']
                    for field in password_fields:
                        if field in parsed and parsed[field]:
                            credentials['password'] = parsed[field][0]
                            break
                    
                    if not credentials:
                        for key, value in parsed.items():
                            if value:
                                credentials[key] = value[0]
                except Exception:
                    pass
            
            # Fallback: find credentials in raw text
            if not credentials:
                username_match = re.search(r'(?:username|user|email|login)[\s=:]+([^\s&,]+)', body, re.IGNORECASE)
                if username_match:
                    credentials['username'] = username_match.group(1)
                
                password_match = re.search(r'(?:password|pass|pwd)[\s=:]+([^\s&,]+)', body, re.IGNORECASE)
                if password_match:
                    credentials['password'] = password_match.group(1)
                
                if not credentials:
                    pairs = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)[\s=:]+([^\s&,]+)', body)
                    for key, value in pairs:
                        if key.lower() in ['username', 'user', 'email', 'login']:
                            credentials['username'] = value
                        elif key.lower() in ['password', 'pass', 'pwd']:
                            credentials['password'] = value
                        else:
                            credentials[key] = value
            
            credentials = {k: v for k, v in credentials.items() if v}
            
        except Exception as e:
            print(f"[Debug] Credential extraction error: {e}")
        
        return credentials

    def _build_http_response(self, status_code: int, status_text: str, 
                            body: str = "", content_type: str = "text/html",
                            headers: dict = None) -> bytes:
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "Server: nginx/1.18.0\r\n"
        response += "Connection: close\r\n"
        
        if headers:
            for key, value in headers.items():
                response += f"{key}: {value}\r\n"
        
        response += "\r\n"
        response += body
        return response.encode('utf-8', errors='ignore')

    def _get_success_page(self) -> str:
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="refresh" content="2;url={self.success_redirect}">
            <title>Redirecting...</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    padding: 50px;
                    background: #f0f2f5;
                }}
                .success {{
                    color: #28a745;
                    font-size: 24px;
                    margin-bottom: 20px;
                }}
                .loader {{
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #3498db;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
            </style>
        </head>
        <body>
            <div class="success">✓ Login successful!</div>
            <div class="loader"></div>
            <p>Redirecting you to the homepage...</p>
        </body>
        </html>
        """

    async def start(self):
        max_conn = self.performance_config.get("max_concurrent_connections", 1000)
        server = await asyncio.start_server(
            self._handle_client, 
            "0.0.0.0", 
            self.port,
            limit=max_conn
        )
        return server

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        ip = addr[0] if addr else "unknown"

        captured = ""
        login_data = {}
        response_sent = False

        try:
            read_timeout = self.performance_config.get("read_timeout_seconds", 10)
            buffer_size = self.performance_config.get("socket_buffer_size", 4096)

            if self.banner and not self.is_http:
                writer.write(self.banner.encode(errors="ignore"))
                await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(buffer_size), timeout=read_timeout)
                captured_raw = data.decode(errors="replace").strip()
                captured = captured_raw

                if self.is_http:
                    method, path, headers, body = self._parse_http_request(captured_raw)
                    
                    if method == "POST" and path == self.login_endpoint:
                        login_data = self._extract_credentials(body, headers)
                        
                        if login_data:
                            captured = f"Credentials captured: {login_data}"
                            await self._send_credential_alert(ip, login_data)
                            self._log_credentials_to_file(ip, login_data)
                        else:
                            captured = f"POST data received: {body[:200]}"
                        
                        response_body = self._get_success_page()
                        response = self._build_http_response(200, "OK", response_body)
                        writer.write(response)
                        await writer.drain()
                        response_sent = True
                        
                    elif method == "GET":
                        template = self.template_cache.get('main', self._get_default_template())
                        
                        if "success=1" in path:
                            template = template.replace(
                                '<form',
                                '<div style="color:green;text-align:center;margin:10px 0;">✓ Successfully logged in!</div><form'
                            )
                        
                        response = self._build_http_response(200, "OK", template)
                        writer.write(response)
                        await writer.drain()
                        response_sent = True
                        captured = f"Page visit: {path}"

            except asyncio.TimeoutError:
                captured = "(no data sent - timeout)"
            except UnicodeDecodeError:
                captured = "(binary data received)"
            except Exception as e:
                captured = f"(error reading data: {str(e)})"

            if not self.is_http and not response_sent:
                name_lower = self.name.lower()
                if name_lower in ("ssh", "telnet", "ftp"):
                    writer.write(b"Login incorrect\r\n")
                await writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            captured = captured or "(connection reset)"
        except Exception as e:
            captured = f"(error: {str(e)})"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        await self._record_event(ip, captured, login_data)

    def _log_credentials_to_file(self, ip: str, credentials: dict):
        try:
            cred_log_dir = Path("logs/credentials")
            cred_log_dir.mkdir(parents=True, exist_ok=True)
            
            cred_file = cred_log_dir / "captured_credentials.log"
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(cred_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] IP: {ip} | Service: {self.name} | Port: {self.port}\n")
                for key, value in credentials.items():
                    f.write(f"  {key}: {value}\n")
                f.write("-" * 60 + "\n")
        except Exception as e:
            print(f"[Warning] Could not log credentials to file: {e}")

    async def _send_credential_alert(self, ip: str, login_data: dict):
        if not login_data:
            return
        
        geo = await self.geoip.resolve(ip)
        location = geo.get("location", f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
        
        creds_str = "\n".join([f"• {k}: {v}" for k, v in login_data.items()])
        
        alert_msg = (
            f"🔐 CREDENTIALS CAPTURED!\n\n"
            f"🌐 IP: {ip}\n"
            f"📍 Location: {location}\n"
            f"🏢 ISP: {geo.get('isp', 'Unknown')}\n"
            f"🔌 Service: {self.name} (Port {self.port})\n"
            f"⏰ Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"📝 Credentials:\n{creds_str}"
        )
        
        await self.notifier.send_raw_alert(alert_msg)
        
        print(f"\n{'='*60}")
        print(f"🔐 CREDENTIALS CAPTURED from {ip} ({location})")
        print(f"{'='*60}")
        for key, value in login_data.items():
            print(f"  {key}: {value}")
        print(f"{'='*60}\n")

    async def _record_event(self, ip: str, captured: str, login_data: dict = None):
        geo = await self.geoip.resolve(ip)
        location = geo.get("location", f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")

        event = {
            "ip": ip,
            "port": self.port,
            "service": self.name,
            "captured": captured[:500] + ("..." if len(captured) > 500 else ""),
            "country": geo.get("country"),
            "city": geo.get("city"),
            "isp": geo.get("isp"),
            "location": location,
            "login_data": login_data if login_data else None,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
        await self.logger.log_event(event)

        key = f"{ip}:{self.port}"
        existing = self.dashboard_state.get(key)
        
        dashboard_entry = {
            "ip": ip,
            "service": self.name,
            "port": self.port,
            "country": geo.get("country", "?"),
            "city": geo.get("city", "?"),
            "location": location,
            "last_seen": datetime.datetime.now().strftime("%H:%M:%S"),
            "hits": (existing["hits"] + 1) if existing else 1,
            "last_creds": login_data if login_data else None,
        }
        
        if login_data:
            dashboard_entry["credentials"] = login_data
            
        self.dashboard_state[key] = dashboard_entry

        if not login_data:
            await self.notifier.send_alert(ip, self.port, self.name, geo, extra=captured)
