import os
import re
import logging

from agents.base_agent import BaseAgent


CRITICAL_KEYWORDS = [
    "ddos", "sql injection", "sqli", "injection attempt", "injection",
    "xss", "cross-site", "brute force", "brute-force",
    "port scan", "portscan", "exploit", "malware", "ransomware",
    "backdoor", "rootkit", "command injection", "rce",
    "remote code execution", "buffer overflow", "shellcode",
    "unauthorized access", "privilege escalation",
    "lateral movement", "exfiltration", "data breach",
    "heartbleed", "botnet", "command and control",
    "possible ddos", "possible sql", "possible injection",
]

HIGH_KEYWORDS = [
    "failed login", "authentication failure", "login failed",
    "failed ssh", "ssh login", "login attempts", "failed attempts",
    "invalid password", "wrong password", "access denied",
    "forbidden", "multiple attempts", "repeated attempts",
    "too many requests", "rate limit", "blocked",
    "suspicious", "anomaly", "detected", "intrusion",
    "alert", "warning", "flood", "scan", "probe",
    "enumeration", "fuzzing",
]

MEDIUM_KEYWORDS = [
    "error", "exception", "traceback", "stack trace",
    "timeout", "connection dropped", "reset", "refused",
    "invalid", "malformed", "unexpected", "unknown",
    "permission denied", "not authorized",
]
SAFE_KEYWORDS = [
    "authenticated successfully", "login successful", "success",
    "200 ok", "health check", "ping", "normal", "routine",
    "scheduled", "backup completed", "info:", "debug:",
    "session established", "connected", "approved",
]

SEVERITY_MAP = {
    "critical": 1.0,
    "emergency": 1.0,
    "alert":    0.85,
    "error":    0.60,
    "err":      0.60,
    "warning":  0.45,
    "warn":     0.45,
    "notice":   0.25,
    "info":     0.15,
    "debug":    0.10,
}

# Number-based heuristics
HIGH_COUNT_PATTERN = re.compile(
    r'(\d+)\s*(attempt|connection|request|packet|login|fail)',
    re.IGNORECASE
)

class LogAgent(BaseAgent):

    def __init__(self):
        super().__init__()
        self._pipeline = self._load_bert()

    def _load_bert(self):
        """Try to load DistilBERT as secondary signal. Not required."""
        try:
            from transformers import pipeline
            cache = os.getenv("MODEL_DIR", "models/") + "distilbert"
            clf = pipeline(
                "text-classification",
                model="distilbert-base-uncased-finetuned-sst-2-english",
                cache_dir=cache,
                truncation=True,
                max_length=512,
            )
            self.logger.info("DistilBERT loaded as secondary signal.")
            return clf
        except Exception as e:
            self.logger.info(f"DistilBERT not available ({e}). "
                             f"Using rule-based scoring only.")
            return None

    def predict(self, log_text: str) -> float:
        if not log_text or not log_text.strip():
            return 0.05

        # Primary: rule-based (80% weight)
        rule_score = self._rule_score(log_text)

        # Secondary: DistilBERT (20% weight) -- only as tiebreaker
        if self._pipeline is not None:
            bert_score = self._bert_score(log_text)
            final = 0.80 * rule_score + 0.20 * bert_score
        else:
            final = rule_score

        return self._validate_score(final)

    def _rule_score(self, text: str) -> float:
        t = text.lower()
        score = 0.0
        base = 0.30  # default if no severity prefix found
        for sev, val in SEVERITY_MAP.items():
            if re.search(rf'\b{sev}\b', t):
                base = max(base, val)
                break

        score = base

        critical_hits = sum(1 for kw in CRITICAL_KEYWORDS if kw in t)
        score += min(critical_hits, 3) * 0.35

        high_hits = sum(1 for kw in HIGH_KEYWORDS if kw in t)
        score += min(high_hits, 3) * 0.20

        if critical_hits == 0:
            med_hits = sum(1 for kw in MEDIUM_KEYWORDS if kw in t)
            score += min(med_hits, 3) * 0.10

        # --- High-count heuristic ---
        # "9000 connection attempts" -> very suspicious
        for match in HIGH_COUNT_PATTERN.finditer(text):
            count = int(match.group(1))
            if count > 1000:
                score += 0.30
            elif count > 100:
                score += 0.20
            elif count > 10:
                score += 0.10

        # --- Safe indicators reduce score ---
        safe_hits = sum(1 for kw in SAFE_KEYWORDS if kw in t)
        score -= safe_hits * 0.15

        return float(max(0.0, min(1.0, score)))

    def _bert_score(self, text: str) -> float:
        try:
            result     = self._pipeline(text[:512])[0]
            confidence = float(result["score"])
            label      = result["label"]
            # POSITIVE sentiment in security logs often = alert/danger language
            return confidence if label == "POSITIVE" else 1.0 - confidence
        except Exception:
            return 0.5