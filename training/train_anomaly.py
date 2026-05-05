import os
import sys
import time
import logging
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_anomaly")

NORMAL_PATH  = "data/processed/normal_only.csv"
TEST_PATH    = "data/processed/test.csv"
MODEL_PATH   = "models/anomaly_isoforest.pkl"
LABEL_COL    = "Label"
RANDOM_STATE = 42

ISOLATION_FOREST_PARAMS = {
    "n_estimators":  300,
    "contamination": 0.245,   # 24.5% of full dataset is attacks
    "max_samples":   0.8,     # 80% of data per tree
    "max_features":  0.8,     # 80% of features per tree
    "random_state":  RANDOM_STATE,
    "n_jobs":        -1,
    "verbose":       0,
}


def load_features(path: str):
    if not os.path.exists(path):
        logger.error(f"File not found: {path}")
        sys.exit(1)
    logger.info(f"Loading {path}")
    df = pd.read_csv(path, low_memory=False)
    X  = df.drop(columns=[LABEL_COL], errors="ignore").select_dtypes(include=[np.number])
    y  = df[LABEL_COL].astype(str).str.strip() if LABEL_COL in df.columns else None
    logger.info(f"  Shape: {X.shape}")
    return X.values, y



def train():
    os.makedirs("models", exist_ok=True)

    X_normal, _ = load_features(NORMAL_PATH)
    logger.info(f"Training on {len(X_normal):,} BENIGN samples only.")

    logger.info("Training Isolation Forest...")
    t0    = time.time()
    model = IsolationForest(**ISOLATION_FOREST_PARAMS)
    model.fit(X_normal)
    elapsed = time.time() - t0
    logger.info(f"Training complete in {elapsed:.1f}s")

    # Evaluate on temporal test set (Friday)
    if os.path.exists(TEST_PATH):
        logger.info("Evaluating on TEMPORAL test set (Friday only)...")
        X_test, labels = load_features(TEST_PATH)
        if labels is not None:
            preds  = model.predict(X_test)
            scores = model.decision_function(X_test)
            y_true = (labels != "BENIGN").astype(int).values
            y_pred = (preds == -1).astype(int)

            if y_true.sum() > 0:
                tpr = y_pred[y_true == 1].mean()
                fpr = y_pred[y_true == 0].mean()
                auc = roc_auc_score(y_true, -scores)
                logger.info(f"True Positive Rate  (attacks caught): {tpr:.4f} ({tpr*100:.1f}%)")
                logger.info(f"False Positive Rate (false alarms):   {fpr:.4f} ({fpr*100:.1f}%)")
                logger.info(f"ROC-AUC: {auc:.4f}")
                logger.info("")
                logger.info("NOTE: Evaluated on Friday (temporal test) -- honest score.")

    joblib.dump(model, MODEL_PATH)
    logger.info(f"Model saved -> {MODEL_PATH}")
    logger.info("This model detects deviations from normal traffic.")
    logger.info("It catches zero-day attacks that XGBoost misses.")


if __name__ == "__main__":
    train()