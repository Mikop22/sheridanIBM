from __future__ import annotations

from threading import RLock
from typing import Protocol

from app.domain.contracts import Prediction
from app.domain.errors import PredictionAlreadyExistsError, PredictionNotFoundError


class PredictionRepository(Protocol):
    def create(self, prediction: Prediction) -> Prediction: ...

    def get(self, prediction_id: str) -> Prediction: ...


class InMemoryPredictionRepository:
    """Thread-safe, process-local storage used only for the first milestone."""

    def __init__(self) -> None:
        self._predictions: dict[str, Prediction] = {}
        self._lock = RLock()

    def create(self, prediction: Prediction) -> Prediction:
        with self._lock:
            if prediction.prediction_id in self._predictions:
                raise PredictionAlreadyExistsError(prediction.prediction_id)
            stored = prediction.model_copy(deep=True)
            self._predictions[prediction.prediction_id] = stored
            return stored.model_copy(deep=True)

    def get(self, prediction_id: str) -> Prediction:
        with self._lock:
            try:
                return self._predictions[prediction_id].model_copy(deep=True)
            except KeyError as exc:
                raise PredictionNotFoundError(prediction_id) from exc
