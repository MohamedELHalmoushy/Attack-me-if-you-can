

# import argparse
# import logging
# import os
# import sys

# if hasattr(sys.stdout, 'reconfigure'):
#     sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# from dotenv import load_dotenv
# load_dotenv()

# logging.basicConfig(
#     level=os.getenv("LOG_LEVEL", "INFO"),
#     format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
#     handlers=[
#         logging.StreamHandler(sys.stdout),
#         logging.FileHandler(os.getenv("LOG_FILE", "logs/decisions.log"),
#                             encoding='utf-8'),
#     ],
# )
# logger = logging.getLogger("main")


# def _load_demo_scenarios() -> list:

#     import json
#     import numpy as np
#     import pandas as pd

#     TEST_CSV      = "data/processed/test.csv"
#     FEAT_JSON     = "models/feature_names.json"
#     LABEL_COL     = "Label"

#     LOG_TEXTS = {
#         "DDoS":
#             "CRITICAL: 9000 connection attempts from 192.168.1.105 in 1 second. Possible DDoS.",
#         "FTP-Patator":
#             "WARNING: Multiple failed FTP login attempts for admin from 10.0.0.44. Attempt 47/50.",
#         "Portscan":
#             "WARNING: Sequential port scan detected from 10.0.0.55. Ports 1-1024 scanned.",
#         "Web Attack - SQL Injection":
#             "ERROR: SQL injection in request params: ' OR 1=1 --. Possible SQLi.",
#         "DoS Hulk":
#             "CRITICAL: HTTP flood detected. 5000 requests/sec from single host.",
#         "BENIGN":
#             "INFO: User authenticated successfully. Session established. GET /dashboard 200 OK.",
#     }

#     # Targets: (csv_label, display_name)
#     TARGETS = [
#         ("DDoS",                      "DDoS Attack"),
#         ("Portscan",                   "Port Scan"),
#         ("Web Attack - SQL Injection", "SQL Injection"),
#         ("BENIGN",                     "Normal Traffic"),
#     ]

#     if not os.path.exists(TEST_CSV):
#         logger.warning(f"test.csv not found -- using zero vectors (run preprocessing first)")
#         # Determine feature count from feature_names.json if available
#         n = 60
#         if os.path.exists(FEAT_JSON):
#             with open(FEAT_JSON) as f:
#                 n = len(json.load(f))
#         return [
#             {"name": name, "features": [0.0] * n,
#              "log_text": LOG_TEXTS.get(lbl, f"Network event: {lbl}")}
#             for lbl, name in TARGETS
#         ]

#     logger.info("Loading demo samples from test.csv...")
#     df = pd.read_csv(TEST_CSV, low_memory=False)
#     df.columns = df.columns.str.strip()
#     if LABEL_COL in df.columns:
#         df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()

#     feat_cols = [c for c in df.columns if c != LABEL_COL]
#     numeric   = df[feat_cols].select_dtypes(include=[np.number]).columns.tolist()

#     scenarios = []
#     for csv_label, display_name in TARGETS:
#         # Exact match first, then partial
#         subset = df[df[LABEL_COL] == csv_label]
#         if len(subset) == 0:
#             word = csv_label.split()[0]
#             subset = df[df[LABEL_COL].str.contains(word, case=False, na=False)]
#         if len(subset) == 0:
#             logger.warning(f"  No samples for label: {csv_label} -- skipping")
#             continue

#         row      = subset.sample(1, random_state=42).iloc[0]
#         features = row[numeric].fillna(0).tolist()
#         log_text = LOG_TEXTS.get(csv_label, f"Network event classified as: {csv_label}")
#         scenarios.append({"name": display_name, "features": features, "log_text": log_text})
#         logger.info(f"  Loaded: {display_name:<25} ({len(features)} features)")

#     return scenarios


# DEMO_SCENARIOS = _load_demo_scenarios()

# def run_pipeline(features: list, log_text: str, scenario_name: str = "Sample") -> dict:
#     from agents.ids_agent import IDSAgent
#     from agents.anomaly_agent import AnomalyAgent
#     from agents.log_agent import LogAgent
#     from core.risk_fusion import RiskFusionEngine
#     from core.response_agent import ResponseAgent

#     logger.info(f"Processing scenario: {scenario_name}")

#     ids_score     = IDSAgent().predict(features)
#     anomaly_score = AnomalyAgent().predict(features)
#     log_score     = LogAgent().predict(log_text)

#     logger.info(f"IDS={ids_score:.3f}  Anomaly={anomaly_score:.3f}  Log={log_score:.3f}")

#     final_score, risk_level = RiskFusionEngine().fuse(ids_score, anomaly_score, log_score)
#     logger.info(f"Fused score={final_score:.3f}  Level={risk_level}")

#     result = ResponseAgent().act(final_score, risk_level)

#     return {
#         "scenario":      scenario_name,
#         "ids_score":     round(ids_score, 3),
#         "anomaly_score": round(anomaly_score, 3),
#         "log_score":     round(log_score, 3),
#         "final_score":   round(final_score, 3),
#         "risk_level":    risk_level,
#         "action":        result["action"],
#     }


# def print_result(r: dict):
#     icons = {"CRITICAL": "[!!]", "HIGH": "[! ]", "MEDIUM": "[ !]", "LOW": "[  ]"}
#     bar  = "-" * 50
#     icon = icons.get(r["risk_level"], "[  ]")
#     print(f"\n{bar}")
#     print(f"  Scenario  : {r['scenario']}")
#     print(f"  IDS       : {r['ids_score']:.3f}")
#     print(f"  Anomaly   : {r['anomaly_score']:.3f}")
#     print(f"  Log       : {r['log_score']:.3f}")
#     print(f"  Final     : {r['final_score']:.3f}  ->  {icon} {r['risk_level']}")
#     print(f"  Action    : {r['action']}")
#     print(bar)


# def parse_args():
#     p = argparse.ArgumentParser(description="AI Cyber Defense System")
#     p.add_argument("--demo",   action="store_true", help="Run demo scenarios")
#     p.add_argument("--sample", type=str, default=None, help="Path to CSV sample")
#     return p.parse_args()


# def main():
#     args = parse_args()

#     if args.demo:
#         logger.info(f"Running demo mode -- {len(DEMO_SCENARIOS)} scenarios")
#         for s in DEMO_SCENARIOS:
#             r = run_pipeline(s["features"], s["log_text"], s["name"])
#             print_result(r)
#         return

#     if args.sample:
#         import pandas as pd
#         df       = pd.read_csv(args.sample)
#         features = df.iloc[0].drop("Label", errors="ignore").tolist()
#         r        = run_pipeline(features, "Sample from CSV.", "CSV Sample")
#         print_result(r)
#         return

#     # Default: single DDoS demo
#     if not DEMO_SCENARIOS:
#         logger.error("No demo scenarios loaded. Run preprocessing first.")
#         return
#     s = DEMO_SCENARIOS[0]
#     r = run_pipeline(s["features"], s["log_text"], s["name"])
#     print_result(r)
#     print("\nTip: run with --demo to see all scenarios.")
#     print("     run with --sample path/to/file.csv to test your own data.")


# if __name__ == "__main__":
#     main()
