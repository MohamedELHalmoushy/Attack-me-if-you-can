from abc import ABC, abstractmethod
import logging


class BaseAgent(ABC):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._model = None

    @abstractmethod
    def predict(self, input_data) -> float:

        ...

    def _validate_score(self, score: float) -> float:
        if not (0.0 <= score <= 1.0):
            self.logger.warning(f"Score {score:.4f} out of [0,1] — clamping.")
            return float(max(0.0, min(1.0, score)))
        return float(score)
