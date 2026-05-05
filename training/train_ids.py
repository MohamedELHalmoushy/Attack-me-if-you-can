import os
import sys
import time
import json
import logging
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, classification_report
from xgboost import XGBClassifier
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_ids")


TRAIN_PATH   = "data/processed/train.csv"
TEST_PATH    = "data/processed/test.csv"
MODEL_PATH   = "models/ids_xgboost.pkl"
WEIGHTS_PATH = "models/class_weights.json"
LABEL_COL    = "Label"
RANDOM_STATE = 42

XGBOOST_PARAMS = {
    "n_estimators":     200,
    "max_depth":        6,
    "learning_rate":    0.1,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "eval_metric":      "mlogloss",
    "use_label_encoder": False,
    "n_jobs":           -1,
    "random_state":     RANDOM_STATE,
    "verbosity":        0,
}


def load_data(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        logger.error(f"File not found: {path}. Run data/preprocessing.py first.")
        sys.exit(1)
    logger.info(f"Loading {path}")
    df = pd.read_csv(path, low_memory=False)
    logger.info(f"  Shape: {df.shape}")
    return df


def prepare_xy(df: pd.DataFrame, le: LabelEncoder = None, fit: bool = False):
    if LABEL_COL not in df.columns:
        logger.error(f"Label column '{LABEL_COL}' not found.")
        sys.exit(1)
    X     = df.drop(columns=[LABEL_COL]).select_dtypes(include=[np.number])
    y_raw = df[LABEL_COL].astype(str).str.strip()
    if fit:
        le = LabelEncoder()
        y  = le.fit_transform(y_raw)
    else:
        # Handle unseen labels in test set gracefully
        known = set(le.classes_)
        y_raw = y_raw.apply(lambda x: x if x in known else "BENIGN")
        y     = le.transform(y_raw)
    return X.values, y, le


def build_sample_weights(y_encoded: np.ndarray, le: LabelEncoder,
                          weights_dict: dict) -> np.ndarray:
    """
    Fix 1: Convert class_weights.json into a per-sample weight array.
    XGBoost.fit(sample_weight=...) upweights rare classes during training.
    """
    w = np.ones(len(y_encoded), dtype=np.float32)
    for label, weight in weights_dict.items():
        if label in le.classes_:
            idx = np.where(le.classes_ == label)[0][0]
            w[y_encoded == idx] = weight
    return w


def train():
    os.makedirs("models", exist_ok=True)

    # Load class weights (Fix 1)
    weights_dict = {}
    if os.path.exists(WEIGHTS_PATH):
        with open(WEIGHTS_PATH) as f:
            weights_dict = json.load(f)
        logger.info(f"Loaded class weights from {WEIGHTS_PATH}")
        logger.info(f"  Example -- Heartbleed weight: "
                    f"{weights_dict.get('Heartbleed', 'N/A')}")
    else:
        logger.warning(f"class_weights.json not found -- training without weights.")

    # Load data
    train_df = load_data(TRAIN_PATH)
    test_df  = load_data(TEST_PATH)

    X_train, y_train, le = prepare_xy(train_df, fit=True)
    X_test,  y_test,  _  = prepare_xy(test_df, le=le, fit=False)

    logger.info(f"Classes ({len(le.classes_)}): {list(le.classes_)}")

    benign_idx = int(np.where(le.classes_ == "BENIGN")[0][0]) \
                 if "BENIGN" in le.classes_ else 0
    logger.info(f"BENIGN class index: {benign_idx}")

    # Build sample weights (Fix 1)
    if weights_dict:
        sw = build_sample_weights(y_train, le, weights_dict)
        logger.info(f"Sample weights: min={sw.min():.4f}  max={sw.max():.4f}  "
                    f"mean={sw.mean():.4f}")
    else:
        sw = None

    # Train
    logger.info("Training XGBoost with sample weights (Fix 1)...")
    t0    = time.time()
    model = XGBClassifier(**XGBOOST_PARAMS)
    model.fit(X_train, y_train, sample_weight=sw)
    elapsed = time.time() - t0
    logger.info(f"Training complete in {elapsed:.1f}s")

    model.benign_class_index_ = benign_idx

    # Evaluate
    logger.info("Evaluating on TEMPORAL test set (Friday only)...")
    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    f1     = f1_score(y_test, y_pred, average="weighted")

    logger.info(f"Accuracy (temporal): {acc:.4f} ({acc*100:.2f}%)")
    logger.info(f"F1 Score (weighted): {f1:.4f}")
    logger.info("")
    logger.info("NOTE: Accuracy on temporal test is the HONEST score.")
    logger.info("      Lower than 100% is expected and correct.")

    sep = "-" * 60
    print(f"\n{sep}")
    labels = np.unique(y_test)

    print(classification_report(
        y_test,
        y_pred,
        labels=labels,
        target_names=le.classes_[labels],
        zero_division=0
    ))
    print(sep)

    # Save
    joblib.dump(model, MODEL_PATH)
    logger.info(f"Model saved -> {MODEL_PATH}")

    le_path = MODEL_PATH.replace(".pkl", "_label_encoder.pkl")
    joblib.dump(le, le_path)
    logger.info(f"Label encoder saved -> {le_path}")


if __name__ == "__main__":
    train()