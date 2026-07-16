"""
JSON event logger for GYRO Honeypot.
Writes events as newline-delimited JSON (JSONL) for easy processing.
"""

import json
import os
from pathlib import Path
from datetime import datetime
import asyncio


class EventLogger:
    def __init__(self, log_dir: str, log_file: str, max_size_mb: int = 100, backup_count: int = 5):
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / log_file
        self.max_size_mb = max_size_mb
        self.backup_count = backup_count
        self._lock = asyncio.Lock()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create credentials subdirectory
        self.cred_dir = self.log_dir / "credentials"
        self.cred_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file = self.cred_dir / "captured_credentials.log"

    async def log_event(self, event: dict):
        """Log an event as JSON to the log file."""
        async with self._lock:
            try:
                # Add timestamp if not present
                if "timestamp" not in event:
                    event["timestamp"] = datetime.utcnow().isoformat() + "Z"
                
                # Check file size and rotate if needed
                if self.log_file.exists() and self.log_file.stat().st_size > (self.max_size_mb * 1024 * 1024):
                    self._rotate_logs()
                
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            except Exception as e:
                print(f"[Error] Failed to log event: {e}")

    async def log_credentials(self, ip: str, service: str, port: int, credentials: dict):
        """Log captured credentials to a separate file."""
        async with self._lock:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                with open(self.cred_file, "a", encoding="utf-8") as f:
                    f.write(f"[{timestamp}] IP: {ip} | Service: {service} | Port: {port}\n")
                    for key, value in credentials.items():
                        f.write(f"  {key}: {value}\n")
                    f.write("-" * 60 + "\n")
            except Exception as e:
                print(f"[Error] Failed to log credentials: {e}")

    def _rotate_logs(self):
        """Rotate log files when size limit is reached."""
        try:
            # Remove oldest backup if exists
            oldest = self.log_file.parent / f"{self.log_file.stem}.{self.backup_count}{self.log_file.suffix}"
            if oldest.exists():
                oldest.unlink()
            
            # Rotate existing backups
            for i in range(self.backup_count - 1, 0, -1):
                src = self.log_file.parent / f"{self.log_file.stem}.{i}{self.log_file.suffix}"
                dst = self.log_file.parent / f"{self.log_file.stem}.{i+1}{self.log_file.suffix}"
                if src.exists():
                    src.rename(dst)
            
            # Rename current log
            if self.log_file.exists():
                self.log_file.rename(
                    self.log_file.parent / f"{self.log_file.stem}.1{self.log_file.suffix}"
                )
        except Exception as e:
            print(f"[Error] Failed to rotate logs: {e}")

    def read_events(self, limit: int = 100):
        """Read recent events from the log file."""
        events = []
        try:
            if self.log_file.exists():
                with open(self.log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        try:
                            events.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"[Error] Failed to read events: {e}")
        return events