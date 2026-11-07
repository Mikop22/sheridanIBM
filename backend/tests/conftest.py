from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import ExplanationProvider, Settings
from app.main import create_app

BACKEND_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def prediction_payload() -> dict:
    path = BACKEND_ROOT / "contracts/v1/examples/prediction-create.synthetic.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def client() -> TestClient:
    app = create_app(Settings(explanation_provider=ExplanationProvider.LOCAL))
    with TestClient(app) as test_client:
        yield test_client
