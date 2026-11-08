from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PREDICTION_ARTIFACT = REPOSITORY_ROOT / "model" / "results" / "submission_v1_summary.json"


class ExplanationProvider(StrEnum):
    LOCAL = "local"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    WATSONX = "watsonx"


class Settings(BaseSettings):
    """Runtime configuration. Local mode has no external dependencies."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    explanation_provider: ExplanationProvider = ExplanationProvider.LOCAL
    provider_connect_timeout: float = Field(default=5.0, gt=0)
    provider_read_timeout: float = Field(default=30.0, gt=0)
    provider_max_output_tokens: int = Field(default=700, ge=1, le=4096)

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "granite4:3b"

    hf_token: str = ""
    hf_model_id: str = ""
    hf_response_model_id: str = ""

    cors_allowed_origins: str = ""

    watsonx_api_key: str = ""
    watsonx_project_id: str = ""
    watsonx_url: str = ""
    watsonx_model_id: str = ""

    event_database_path: Path = Path("security_events.db")
    event_risk_threshold: float | None = None
    event_threshold_scale_minimum: float | None = None
    event_threshold_scale_maximum: float | None = None
    event_threshold_higher_is_riskier: bool | None = None

    prediction_artifact_path: Path = DEFAULT_PREDICTION_ARTIFACT
    prediction_artifact_min_snapshot_month: str | None = None

    @field_validator("prediction_artifact_min_snapshot_month")
    @classmethod
    def validate_snapshot_month(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if (
            len(normalized) != 7
            or normalized[4] != "-"
            or not normalized[:4].isdigit()
            or not normalized[5:].isdigit()
            or not 1 <= int(normalized[5:]) <= 12
        ):
            raise ValueError("PREDICTION_ARTIFACT_MIN_SNAPSHOT_MONTH must use YYYY-MM")
        return normalized

    @field_validator("cors_allowed_origins")
    @classmethod
    def reject_wildcard_cors(cls, value: str) -> str:
        origins = [item.strip() for item in value.split(",") if item.strip()]
        if "*" in origins:
            raise ValueError("CORS_ALLOWED_ORIGINS must contain explicit origins, not '*'")
        return value

    @field_validator("ollama_base_url")
    @classmethod
    def require_local_ollama(cls, value: str) -> str:
        """Keep Ollama inference on an explicit loopback HTTP endpoint."""
        parsed = urlsplit(value.strip())
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("OLLAMA_BASE_URL must be a loopback HTTP origin")
        return value.strip().rstrip("/")

    def allowed_cors_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_allowed_origins.split(",") if item.strip()]

    def provider_ready(self) -> bool:
        if self.explanation_provider is ExplanationProvider.LOCAL:
            return True
        if self.explanation_provider is ExplanationProvider.OLLAMA:
            return bool(self.ollama_base_url and self.ollama_model.strip())
        if self.explanation_provider is ExplanationProvider.HUGGINGFACE:
            return bool(self.hf_token.strip() and self.hf_model_id.strip())
        return all(
            value.strip()
            for value in (
                self.watsonx_api_key,
                self.watsonx_project_id,
                self.watsonx_url,
                self.watsonx_model_id,
            )
        )


def get_settings() -> Settings:
    return Settings()
