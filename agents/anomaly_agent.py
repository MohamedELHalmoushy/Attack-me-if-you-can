import os
import numpy as np
from agents.base_agent import BaseAgent

MODEL_PATH = os.getenv("MODEL_DIR", "models/") + "anomaly_isoforest.pkl"


class AnomalyAgent(BaseAgent):
    def __init__(self, model_path: str = MODEL_PATH):
        super().__init__()
        self.model_path = model_path
        self._model = self._load_model()

    def _load_model(self):
        import joblib
        if not os.path.exists(self.model_path):
            self.logger.warning(
                f"Anomaly model not found at {self.model_path}. "
                "Run training/train_anomaly.py first. "
                "Returning neutral score 0.5 until trained."
            )
            return None
        self.logger.info(f"Loading Anomaly model from {self.model_path}")
        return joblib.load(self.model_path)

    def predict(self, features: list) -> float:
        if self._model is None:
            self.logger.warning("No model loaded — returning 0.5 (neutral score).")
            return 0.5

        x = np.array(features, dtype=np.float32).reshape(1, -1)

        # decision_function: negative = anomalous, positive = normal
        raw_score = self._model.decision_function(x)[0]

        # Sigmoid transform: maps raw score to [0, 1]
        # Multiplier=2 sharpens the transition at zero
        # Negative raw_score → sigmoid > 0.5 → high anomaly
        normalised = 1.0 / (1.0 + np.exp(raw_score * 2))

        return self._validate_score(float(normalised))
