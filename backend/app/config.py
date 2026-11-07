from enum import StrEnum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ExplanationProvider(StrEnum):
    LOCAL = "local"
    HUGGINGFACE = "huggingface"
    WATSONX = "watsonx"


class Settings(BaseSettings):
    """Runtime configuration. Local mode has no external dependencies."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    explanation_provider: ExplanationProvider = ExplanationProvider.LOCAL
    provider_connect_timeout: float = Field(default=5.0, gt=0)
    provider_read_timeout: float = Field(default=30.0, gt=0)
    provider_max_output_tokens: int = Field(default=700, ge=1, le=4096)

    hf_token: str = ""
    hf_model_id: str = ""

    watsonx_api_key: str = ""
    watsonx_project_id: str = ""
    watsonx_url: str = ""
    watsonx_model_id: str = ""

    event_database_path: Path = Path("security_events.db")
    event_risk_threshold: float | None = None
    event_threshold_scale_minimum: float | None = None
    event_threshold_scale_maximum: float | None = None
    event_threshold_higher_is_riskier: bool | None = None

    def provider_ready(self) -> bool:
        if self.explanation_provider is ExplanationProvider.LOCAL:
            return True
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
