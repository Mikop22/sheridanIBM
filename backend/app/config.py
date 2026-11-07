from enum import StrEnum

from pydantic_settings import BaseSettings, SettingsConfigDict


class ExplanationProvider(StrEnum):
    LOCAL = "local"
    WATSONX = "watsonx"


class Settings(BaseSettings):
    """Runtime configuration. Local mode has no external dependencies."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    explanation_provider: ExplanationProvider = ExplanationProvider.LOCAL


def get_settings() -> Settings:
    return Settings()
