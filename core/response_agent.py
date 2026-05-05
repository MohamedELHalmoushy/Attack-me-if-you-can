import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
load_dotenv()
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logger = logging.getLogger(__name__)

LOG_FILE = os.getenv("LOG_FILE", "logs/decisions.log")


class ResponseAgent:

    ACTIONS = {
        "CRITICAL": "BLOCK_IP",
        "HIGH":     "SEND_ALERT",
        "MEDIUM":   "MONITOR",
        "LOW":      "LOG_ONLY",
    }

    COLORS = {
        "CRITICAL": "[CRITICAL]",
        "HIGH":     "[HIGH]",
        "MEDIUM":   "[MEDIUM]",
        "LOW":      "[LOW]",
    }

    def __init__(self, log_file: str = LOG_FILE):
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def act(
        self,
        final_score: float,
        risk_level: str,
        source_ip: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> dict:
        action = self.ACTIONS.get(risk_level, "LOG_ONLY")

        entry = {
            "timestamp":  datetime.now().isoformat(),
            "risk_level": risk_level,
            "score":      round(final_score, 4),
            "action":     action,
            "source_ip":  source_ip or "unknown",
            "details":    details or {},
        }

        # Log to file
        self._write_log(entry)

        # Console output
        icon = self.COLORS.get(risk_level, "[?]")
        logger.info(f"{icon} {risk_level} [{final_score:.3f}] -> {action}")

        # Dispatch action
        self._dispatch(action, entry)

        return entry

    def _dispatch(self, action: str, entry: dict):
        if action == "BLOCK_IP":
            self._block_ip(entry)
        elif action == "SEND_ALERT":
            self._send_alert(entry)
        elif action == "MONITOR":
            self._escalate_monitoring(entry)
        elif action == "LOG_ONLY":
            pass   # already logged above

    def _block_ip(self, entry: dict):
        ip = entry.get("source_ip", "unknown")
        logger.warning(f"[BLOCK_IP] Blocking {ip} -- score {entry['score']:.3f}")
        # TODO: requests.post("http://firewall/api/block", json={"ip": ip})


    def _send_alert(self, entry: dict):
        email_to = os.getenv("ALERT_EMAIL", "security@example.com")
        email_user = os.getenv("EMAIL_USER")
        email_pass = os.getenv("EMAIL_PASS")
        print("EMAIL USER:", email_user)
        print("EMAIL PASS:", email_pass)
        print("SENDING EMAIL...")
        if not email_user or not email_pass:
            logger.error("Email credentials not set in environment variables")
            return

        subject = "🚨 Security Alert"
        body = f"""
        Threat detected!

        Risk Level: {entry['risk_level']}
        Score: {entry['score']}
        IP: {entry['source_ip']}
        Time: {entry['timestamp']}
        """

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = email_user
        msg["To"] = email_to

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(email_user, email_pass)
                server.send_message(msg)

            logger.warning(f"[EMAIL SENT] Alert sent to {email_to}")

        except Exception as e:
            print("EMAIL ERROR:", e)
            logger.error(f"Failed to send email: {e}")

    def _escalate_monitoring(self, entry: dict):
        logger.info(f"[MONITOR] Escalating monitoring for IP {entry.get('source_ip')}")

    def _write_log(self, entry: dict):
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write decision log: {e}")

    def get_recent_decisions(self, n: int = 50) -> list:
        if not os.path.exists(self.log_file):
            return []
        try:
            with open(self.log_file) as f:
                lines = f.readlines()
            records = []
            for line in lines[-n:]:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
            return list(reversed(records))   # newest first
        except Exception as e:
            logger.error(f"Failed to read decision log: {e}")
            return []