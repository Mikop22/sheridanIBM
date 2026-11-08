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


class EventStoreUnavailableError(Exception):
    """Raised when transient SQLite contention prevents event workflow access."""


class EventAlreadyExistsError(Exception):
    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        super().__init__(f"event {event_id!r} already exists with different content")


class EventNotFoundError(Exception):
    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        super().__init__(f"event {event_id!r} was not found")


class RecommendationNotFoundError(Exception):
    def __init__(self, recommendation_id: str) -> None:
        self.recommendation_id = recommendation_id
        super().__init__(f"recommendation {recommendation_id!r} was not found")


class HistoricalDataUnavailableError(Exception):
    def __init__(self, month: str) -> None:
        self.month = month
        super().__init__(f"historical data for {month!r} is unavailable")


class UnsupportedHistoricalMonthError(Exception):
    def __init__(self, month: str) -> None:
        self.month = month
        super().__init__(f"historical month {month!r} is unsupported")


class InvalidRecommendationTransitionError(Exception):
    def __init__(self, recommendation_id: str, current_status: str) -> None:
        self.recommendation_id = recommendation_id
        self.current_status = current_status
        super().__init__(
            f"recommendation {recommendation_id!r} cannot be changed from {current_status!r}"
        )
