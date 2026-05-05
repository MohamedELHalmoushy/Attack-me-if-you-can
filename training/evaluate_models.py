
import argparse
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.getenv("LOG_FILE", "logs/decisions.log")),
    ],
)

logger = logging.getLogger("main")


def _make_features(base: dict, n: int = 60) -> list:
    v = [0.0] * n
    for idx, val in base.items():
        if idx < n:
            v[idx] = float(val)
    return v


DEMO_SCENARIOS = [
    {
        "name": "DDoS Attack",
        "features": _make_features({
            0: 80, 1: 500, 2: 5000, 3: 0, 4: 750000, 5: 0,
            6: 150, 8: 150, 10: 1500000, 11: 10000,
            12: 0.05, 23: 10000, 31: 1, 34: 0, 39: 150, 52: 65535,
        }),
        "log_text": "CRITICAL: 9000 connection attempts from 192.168.1.105 in 1 second. Possible DDoS.",
    },
    {
        "name": "Brute Force SSH",
        "features": _make_features({
            0: 22, 1: 850000, 2: 12, 3: 10, 4: 960, 5: 800,
            6: 80, 8: 80, 10: 1882, 11: 26, 12: 38000,
            23: 14, 24: 12, 30: 1, 31: 1, 34: 1,
            39: 82, 52: 8192, 53: 8192,
        }),
        "log_text": "WARNING: Multiple failed SSH login attempts for root from 10.0.0.44. Attempt 47/50.",
    },
    {
        "name": "SQL Injection",
        "features": _make_features({
            0: 80, 1: 120000, 2: 8, 3: 6, 4: 4800, 5: 3600,
            6: 600, 8: 600, 10: 70000, 11: 116, 12: 8600,
            30: 1, 31: 1, 33: 1, 34: 1, 39: 600,
            52: 65535, 53: 65535,
        }),
        "log_text": "ERROR: Malformed SQL in request params: ' OR 1=1 --. Possible injection attempt.",
    },
    {
        "name": "Normal Traffic",
        "features": _make_features({
            0: 443, 1: 2500000, 2: 25, 3: 20, 4: 18000, 5: 150000,
            6: 720, 8: 720, 10: 67200, 11: 18, 12: 55000,
            30: 1, 31: 1, 34: 1, 38: 0.8, 39: 750,
            52: 65535, 53: 65535, 54: 20,
        }),
        "log_text": "INFO: User authenticated successfully. Session established. GET /dashboard 200 OK.",
    },
]


def run_pipeline(features: list, log_text: str, scenario_name: str = "Sample") -> dict:
    from agents.ids_agent import IDSAgent
    from agents.anomaly_agent import AnomalyAgent
    from agents.log_agent import LogAgent
    from core.risk_fusion import RiskFusionEngine
    from core.response_agent import ResponseAgent

    logger.info(f"Processing scenario: {scenario_name}")

    ids_score     = IDSAgent().predict(features)
    anomaly_score = AnomalyAgent().predict(features)
    log_score     = LogAgent().predict(log_text)

    logger.info(f"IDS={ids_score:.3f}  Anomaly={anomaly_score:.3f}  Log={log_score:.3f}")

    final_score, risk_level = RiskFusionEngine().fuse(ids_score, anomaly_score, log_score)
    logger.info(f"Fused score={final_score:.3f}  Level={risk_level}")

    result = ResponseAgent().act(final_score, risk_level)

    return {
        "scenario":      scenario_name,
        "ids_score":     round(ids_score, 3),
        "anomaly_score": round(anomaly_score, 3),
        "log_score":     round(log_score, 3),
        "final_score":   round(final_score, 3),
        "risk_level":    risk_level,
        "action":        result["action"],
    }


def print_result(r: dict):
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    bar = "─" * 50
    icon = icons.get(r["risk_level"], "⚪")
    print(f"\n{bar}")
    print(f"  Scenario  : {r['scenario']}")
    print(f"  IDS       : {r['ids_score']:.3f}")
    print(f"  Anomaly   : {r['anomaly_score']:.3f}")
    print(f"  Log       : {r['log_score']:.3f}")
    print(f"  Final     : {r['final_score']:.3f}  →  {icon} {r['risk_level']}")
    print(f"  Action    : {r['action']}")
    print(bar)


def parse_args():
    parser = argparse.ArgumentParser(description="AI Cyber Defense System")
    parser.add_argument("--demo",   action="store_true", help="Run 4 built-in demo scenarios")
    parser.add_argument("--sample", type=str, default=None, help="Path to a single-row CSV sample")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.demo:
        logger.info("Running demo mode — 4 scenarios")
        for s in DEMO_SCENARIOS:
            r = run_pipeline(s["features"], s["log_text"], s["name"])
            print_result(r)
        return

    if args.sample:
        import pandas as pd
        df = pd.read_csv(args.sample)
        features = df.iloc[0].drop("Label", errors="ignore").tolist()
        log_text = "Sample from CSV — no log text available."
        r = run_pipeline(features, log_text, "CSV Sample")
        print_result(r)
        return

    logger.info("No arguments — running single DDoS demo.")
    s = DEMO_SCENARIOS[0]
    r = run_pipeline(s["features"], s["log_text"], s["name"])
    print_result(r)
    print("\nTip: run with --demo to see all 4 scenarios.")
    print("     run with --sample path/to/file.csv to test your own data.")


if __name__ == "__main__":
    main()
