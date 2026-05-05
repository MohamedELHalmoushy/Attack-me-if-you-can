import os
import numpy as np
from agents.base_agent import BaseAgent
MODEL_PATH = os.getenv("MODEL_DIR", "models/") + "ids_xgboost.pkl"

class IDSAgent(BaseAgent):
    def __init__(self, model_path: str = MODEL_PATH):
        super().__init__()
        self.model_path = model_path
        self._model = self._load_model()

    def _load_model(self):
        import joblib
        if not os.path.exists(self.model_path):
            self.logger.warning(
                f"Model not found at {self.model_path}. "
                "Run training/train_ids.py first. "
                "Returning dummy score 0.5 until model is trained."
            )
            return None
        self.logger.info(f"Loading IDS model from {self.model_path}")
        return joblib.load(self.model_path)

    def predict(self, features: list) -> float:
        if self._model is None:
            self.logger.warning("No model loaded — returning 0.5 (neutral score).")
            return 0.5

        x = np.array(features, dtype=np.float32).reshape(1, -1)
        proba = self._model.predict_proba(x)[0]
        if len(proba) == 2:
            score = float(proba[1])
        else:
            benign_idx = getattr(self._model, "benign_class_index_", 0)
            score = 1.0 - float(proba[benign_idx])

        return self._validate_score(score)
