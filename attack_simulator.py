import argparse
import logging
import os
import sys
import time
import random
import json
from dotenv import load_dotenv
load_dotenv()
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from dotenv import load_dotenv
load_dotenv()

# Suppress noisy logs during simulation
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/decisions.log", encoding='utf-8'),
    ]
)


ATTACK_CATALOGUE = {
    "ddos": {
        "display":     "DDoS Attack",
        "description": "Distributed Denial of Service -- 9,000 req/sec flood",
        "label":       "DDoS",
        "log_text":    "CRITICAL: 9000 connection attempts from 192.168.1.105 in 1 second. SYN flood detected. Possible DDoS attack.",
        "severity":    "CRITICAL",
        "expected":    "CRITICAL/HIGH",
    },
    "portscan": {
        "display":     "Port Scan",
        "description": "Sequential scan of ports 1-65535 from single host",
        "label":       "Portscan",
        "log_text":    "WARNING: Sequential port scan detected from 10.0.0.55. 1024 ports scanned in 3 seconds. Probe activity.",
        "severity":    "WARNING",
        "expected":    "HIGH",
    },
    "bruteforce": {
        "display":     "SSH Brute Force",
        "description": "Dictionary attack on SSH -- 150 attempts/min",
        "label":       "FTP-Patator",
        "log_text":    "WARNING: Multiple failed SSH login attempts for root from 10.0.0.44. 47 failed attempts in 30 seconds. Brute force suspected.",
        "severity":    "WARNING",
        "expected":    "HIGH",
    },
    "sqli": {
        "display":     "SQL Injection",
        "description": "Malicious SQL payload in HTTP request parameters",
        "label":       "Web Attack - SQL Injection",
        "log_text":    "ERROR: SQL injection detected in request params: ' OR 1=1 --. Possible database compromise attempt.",
        "severity":    "ERROR",
        "expected":    "HIGH",
    },
    "dos": {
        "display":     "DoS Hulk",
        "description": "HTTP flood -- randomised headers to bypass caching",
        "label":       "DoS Hulk",
        "log_text":    "CRITICAL: HTTP flood detected. 5000 requests/sec from 10.0.0.88. DoS attack in progress.",
        "severity":    "CRITICAL",
        "expected":    "HIGH/CRITICAL",
    },
    "heartbleed": {
        "display":     "Heartbleed",
        "description": "OpenSSL memory leak exploit -- reads server memory",
        "label":       "Heartbleed",
        "log_text":    "CRITICAL: Heartbleed exploit attempt detected on TLS handshake from 192.168.1.200. Memory leak attack.",
        "severity":    "CRITICAL",
        "expected":    "CRITICAL",
    },
    "botnet": {
        "display":     "Botnet C2",
        "description": "Command & Control communication from infected host",
        "label":       "Botnet",
        "log_text":    "ALERT: Botnet command and control traffic detected from 10.0.0.77. Beacon interval 30s. Host compromised.",
        "severity":    "ALERT",
        "expected":    "HIGH/CRITICAL",
    },
    "infiltration": {
        "display":     "Infiltration",
        "description": "Internal network reconnaissance after initial breach",
        "label":       "Infiltration - Portscan",
        "log_text":    "ERROR: Internal network scan from compromised host 10.0.1.15. Lateral movement detected. Possible infiltration.",
        "severity":    "ERROR",
        "expected":    "HIGH",
    },
    "normal": {
        "display":     "Normal Traffic",
        "description": "Legitimate HTTPS browsing session",
        "label":       "BENIGN",
        "log_text":    "INFO: User authenticated successfully. Session established. GET /dashboard 200 OK. Normal activity.",
        "severity":    "INFO",
        "expected":    "LOW",
    },
    "zeroday": {
        "display":     "Zero-Day (Unknown)",
        "description": "Novel attack -- IDS has never seen this pattern",
        "label":       None, 
        "log_text":    "WARNING: Unusual traffic pattern detected. No known signature match. Anomaly score high.",
        "severity":    "WARNING",
        "expected":    "HIGH (zero-day rule)",
    },
}

LEVEL_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[33m",  # dark yellow
    "LOW":      "\033[92m",  # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[96m"
GRAY  = "\033[90m"


class AttackDataLoader:
    """Loads real feature vectors from test.csv for each attack label."""

    def __init__(self):
        self.df         = None
        self.feat_cols  = []
        self._load()

    def _load(self):
        import pandas as np_pd
        import numpy as np
        path = "data/processed/test.csv"
        if not os.path.exists(path):
            print(f"  [!] test.csv not found -- using synthetic features")
            return
        self.df = np_pd.read_csv(path, low_memory=False)
        self.df.columns = self.df.columns.str.strip()
        if "Label" in self.df.columns:
            self.df["Label"] = self.df["Label"].astype(str).str.strip()
        self.feat_cols = [c for c in self.df.columns if c != "Label"]
        self.feat_cols = self.df[self.feat_cols].select_dtypes(include=[np.number]).columns.tolist()

    def get_features(self, label: str, seed: int = None) -> list:
        """Get a real feature vector for the given attack label."""
        import numpy as np

        if self.df is None or label is None:
            # Synthetic zero-day: random anomalous values
            rng = np.random.RandomState(seed or random.randint(0, 9999))
            n   = len(self.feat_cols) if self.feat_cols else 60
            return rng.uniform(0.5, 2.0, n).tolist()

        subset = self.df[self.df["Label"] == label]
        if len(subset) == 0:
            # Partial match
            word    = label.split()[0]
            subset  = self.df[self.df["Label"].str.contains(word, case=False, na=False)]
        if len(subset) == 0:
            # Fallback: random sample from any attack
            subset = self.df[self.df["Label"] != "BENIGN"]

        rng = np.random.RandomState(seed or random.randint(0, 9999))
        row = subset.sample(1, random_state=int(rng.randint(0, 99999))).iloc[0]
        return row[self.feat_cols].fillna(0).tolist()


def run_attack(attack_key: str, loader: AttackDataLoader,
               seed: int = None, silent: bool = False) -> dict:
    """Run one attack through the full defense pipeline."""
    from agents.ids_agent import IDSAgent
    from agents.anomaly_agent import AnomalyAgent
    from agents.log_agent import LogAgent
    from core.risk_fusion import RiskFusionEngine
    from core.response_agent import ResponseAgent

    attack  = ATTACK_CATALOGUE[attack_key]
    features = loader.get_features(attack["label"], seed=seed)
    log_text = attack["log_text"]

    t0            = time.time()
    ids_score     = IDSAgent().predict(features)
    anomaly_score = AnomalyAgent().predict(features)
    log_score     = LogAgent().predict(log_text)
    elapsed       = time.time() - t0

    result = RiskFusionEngine().fuse_detailed(ids_score, anomaly_score, log_score)
    response = ResponseAgent().act(result.final_score, result.risk_level)

    return {
        "attack_key":   attack_key,
        "display":      attack["display"],
        "description":  attack["description"],
        "expected":     attack["expected"],
        "ids":          round(ids_score, 3),
        "anomaly":      round(anomaly_score, 3),
        "log":          round(log_score, 3),
        "weighted":     round(result.weighted_score, 4),
        "final":        round(result.final_score, 4),
        "level":        result.risk_level,
        "rule":         result.rule_triggered,
        "action":       response["action"],
        "elapsed_ms":   round(elapsed * 1000, 1),
    }


def print_banner():
    print(f"\n{BOLD}{CYAN}")
    print("  start")
  
    print(f"{RESET}")


def print_menu():
    print(f"\n{BOLD}Available Attacks:{RESET}")
    for i, (key, atk) in enumerate(ATTACK_CATALOGUE.items(), 1):
        sev_color = "\033[91m" if atk["severity"] in ("CRITICAL","ALERT") else \
                    "\033[93m" if atk["severity"] == "WARNING" else \
                    "\033[91m" if atk["severity"] == "ERROR" else GRAY
        print(f"  {GRAY}{i:2}.{RESET} {BOLD}{key:<15}{RESET} "
              f"{sev_color}[{atk['severity']:<8}]{RESET} "
              f"{atk['description']}")
    print(f"\n  {GRAY}Commands: auto | stress | quit{RESET}")


def print_result(r: dict, show_detail: bool = True):
    level  = r["level"]
    color  = LEVEL_COLORS.get(level, "")
    action_icons = {
        "BLOCK_IP":   "[!! BLOCKED]",
        "SEND_ALERT": "[!  ALERT  ]",
        "MONITOR":    "[~  MONITOR]",
        "LOG_ONLY":   "[   LOG    ]",
    }
    action_str = action_icons.get(r["action"], r["action"])

    print(f"\n  {'='*54}")
    print(f"  {BOLD}Attack   :{RESET} {r['display']}  {GRAY}-- {r['description']}{RESET}")

    if show_detail:
        print(f"  {BOLD}Agents   :{RESET}  "
              f"IDS={BOLD}{r['ids']:.3f}{RESET}  "
              f"Anomaly={r['anomaly']:.3f}  "
              f"Log={r['log']:.3f}")
        print(f"  {BOLD}Fusion   :{RESET}  "
              f"Weighted={r['weighted']:.3f}  ->  "
              f"Final={BOLD}{r['final']:.3f}{RESET}")
        if r["rule"] != "none":
            print(f"  {BOLD}Smart Rule:{RESET} {CYAN}{r['rule']}{RESET}")

    print(f"  {BOLD}Decision :{RESET}  "
          f"{color}{BOLD}{level:<8}{RESET}  "
          f"{color}{BOLD}{action_str}{RESET}  "
          f"{GRAY}({r['elapsed_ms']}ms){RESET}")

    expected = r["expected"]
    ok = any(level in exp for exp in [expected] + expected.split("/"))
    verdict = f"{BOLD}\033[92m[CORRECT]{RESET}" if ok else f"{BOLD}\033[91m[CHECK]  {RESET}"
    print(f"  {BOLD}Expected :{RESET}  {expected:<10}  {verdict}")
    print(f"  {'='*54}")


def print_summary(results: list):
    print(f"\n{BOLD}{'='*54}")
    print(f"  SIMULATION SUMMARY")
    print(f"{'='*54}{RESET}")

    correct = 0
    for r in results:
        level    = r["level"]
        expected = r["expected"]
        ok       = any(level in exp for exp in [expected] + expected.split("/"))
        if ok:
            correct += 1
        icon  = "\033[92mOK\033[0m" if ok else "\033[91mCHECK\033[0m"
        color = LEVEL_COLORS.get(level, "")
        print(f"  {r['display']:<25} "
              f"{color}{level:<8}{RESET}  "
              f"{r['action']:<12}  {icon}")

    pct = correct / len(results) * 100 if results else 0
    print(f"\n  Correct decisions: {correct}/{len(results)} ({pct:.0f}%)")
    print(f"  Avg response time: "
          f"{sum(r['elapsed_ms'] for r in results)/len(results):.1f}ms")
    print(f"{'='*54}\n")



def run_auto(loader: AttackDataLoader, delay: float = 1.5):
    """Run all attacks in sequence with a short delay between each."""
    print(f"\n{BOLD}[AUTO MODE] Running all {len(ATTACK_CATALOGUE)} attack scenarios...{RESET}\n")
    results = []
    for key in ATTACK_CATALOGUE:
        r = run_attack(key, loader)
        print_result(r)
        results.append(r)
        time.sleep(delay)
    print_summary(results)


def run_stress(loader: AttackDataLoader, n: int = 20):
    """Rapid-fire random attacks -- tests throughput."""
    keys    = list(ATTACK_CATALOGUE.keys())
    results = []
    print(f"\n{BOLD}[STRESS MODE] Firing {n} random attacks...{RESET}\n")
    t_start = time.time()
    for i in range(n):
        key = random.choice(keys)
        r   = run_attack(key, loader, seed=i, silent=True)
        color = LEVEL_COLORS.get(r["level"], "")
        print(f"  [{i+1:2}/{n}] {r['display']:<25} "
              f"{color}{r['level']:<8}\033[0m  "
              f"{r['action']:<12}  "
              f"{GRAY}{r['elapsed_ms']}ms{RESET}")
        results.append(r)
    total = time.time() - t_start
    tps   = n / total
    print(f"\n  Total time: {total:.1f}s  |  Throughput: {tps:.1f} decisions/sec")
    print_summary(results)


def run_single(attack_key: str, loader: AttackDataLoader):
    """Run one specific attack."""
    if attack_key not in ATTACK_CATALOGUE:
        # Try partial match
        matches = [k for k in ATTACK_CATALOGUE if attack_key.lower() in k]
        if matches:
            attack_key = matches[0]
        else:
            print(f"  Unknown attack: {attack_key}")
            print(f"  Available: {list(ATTACK_CATALOGUE.keys())}")
            return
    r = run_attack(attack_key, loader)
    print_result(r)


def interactive(loader: AttackDataLoader):
    """Interactive menu mode."""
    print_banner()
    print_menu()

    keys = list(ATTACK_CATALOGUE.keys())

    while True:
        try:
            raw = input(f"\n{BOLD}> Attack [{'/'.join(keys[:3])}...]: {RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye.")
            break

        if not raw:
            continue
        if raw in ("quit", "exit", "q"):
            print("  Goodbye.")
            break
        if raw in ("auto", "a"):
            run_auto(loader, delay=0.8)
            continue
        if raw.startswith("stress"):
            parts = raw.split()
            n = int(parts[1]) if len(parts) > 1 else 20
            run_stress(loader, n)
            continue
        if raw in ("help", "menu", "?"):
            print_menu()
            continue
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(keys):
                raw = keys[idx]
            else:
                print(f"  Enter a number between 1 and {len(keys)}")
                continue

        if raw in ATTACK_CATALOGUE:
            r = run_attack(raw, loader)
            print_result(r)
        else:
            matches = [k for k in keys if raw in k]
            if matches:
                r = run_attack(matches[0], loader)
                print_result(r)
            else:
                print(f"  Unknown: '{raw}'. Type 'menu' to see options.")


def parse_args():
    p = argparse.ArgumentParser(description="Attack Simulator for AI Cyber Defense")
    p.add_argument("--auto",   action="store_true", help="Run all attacks automatically")
    p.add_argument("--stress", type=int, default=0,  help="Stress test with N random attacks")
    p.add_argument("--attack", type=str, default="", help="Run one specific attack by name")
    p.add_argument("--delay",  type=float, default=1.5, help="Delay between auto attacks (sec)")
    return p.parse_args()


def main():
    args   = parse_args()
    loader = AttackDataLoader()

    if args.attack:
        print_banner()
        run_single(args.attack, loader)
    elif args.auto:
        print_banner()
        run_auto(loader, delay=args.delay)
    elif args.stress > 0:
        print_banner()
        run_stress(loader, n=args.stress)
    else:
        interactive(loader)


if __name__ == "__main__":
    main()