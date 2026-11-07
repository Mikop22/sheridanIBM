class PredictionAlreadyExistsError(Exception):
    def __init__(self, prediction_id: str) -> None:
        self.prediction_id = prediction_id
        super().__init__(f"prediction {prediction_id!r} already exists")


class PredictionNotFoundError(Exception):
    def __init__(self, prediction_id: str) -> None:
        self.prediction_id = prediction_id
        super().__init__(f"prediction {prediction_id!r} was not found")


class ProviderUnavailableError(Exception):
    """Raised when the configured explanation provider cannot serve requests."""
