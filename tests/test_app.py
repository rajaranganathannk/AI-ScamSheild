import json

from app import create_app
from src.database import get_scans, get_statistics


def make_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": tmp_path / "test.sqlite3",
            "MODEL_PATH": tmp_path / "missing.joblib",
        }
    )


def test_home_and_model_status(tmp_path):
    client = make_app(tmp_path).test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishingRisk AI" in response.data
    assert b"Heuristic-only mode" in response.data
    assert response.headers["X-Frame-Options"] == "DENY"


def test_scan_route_validation_and_history(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    assert client.post("/api/scan", json={"url": ""}).status_code == 400
    assert client.post("/api/scan", data="not json").status_code == 400

    response = client.post("/api/scan", json={"url": "https://docs.example.test/help"})
    assert response.status_code == 200
    result = response.get_json()
    assert result["category"] in {"Low", "Medium", "High"}
    assert result["model_available"] is False

    history = client.get("/api/history").get_json()
    assert len(history["scans"]) == 1
    assert history["statistics"]["total"] == 1
    assert get_scans(app.config["DATABASE_PATH"])[0]["url"] == "https://docs.example.test/help"
    assert get_statistics(app.config["DATABASE_PATH"])["total"] == 1


def test_history_clear_route(tmp_path):
    client = make_app(tmp_path).test_client()
    client.post("/api/scan", json={"url": "https://example.test/"})
    response = client.delete("/api/history")
    assert response.status_code == 200
    assert client.get("/api/history").get_json()["statistics"]["total"] == 0


def test_history_redacts_credentials_and_sensitive_query_values(tmp_path):
    client = make_app(tmp_path).test_client()
    response = client.post(
        "/api/scan",
        json={"url": "https://alice:secret@example.test/path?token=abc123&view=public#auth-fragment"},
    )
    assert response.status_code == 200
    history = client.get("/api/history").get_json()["scans"][0]["url"]
    assert "secret" not in history
    assert "abc123" not in history
    assert "auth-fragment" not in history
    assert "[redacted]@example.test" in history
    assert "view=public" in history


def test_request_body_size_limit(tmp_path):
    client = make_app(tmp_path).test_client()
    response = client.post(
        "/api/scan",
        data=json.dumps({"url": "a" * 20_000}),
        content_type="application/json",
    )
    assert response.status_code == 413
