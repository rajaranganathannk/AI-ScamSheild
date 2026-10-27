from src.detector import URLDetector


def test_missing_model_uses_explicit_heuristic_fallback(tmp_path):
    detector = URLDetector(tmp_path / "missing.joblib")
    result = detector.analyze("http://192.0.2.10/login")
    assert detector.model_available is False
    assert result["model_score"] is None
    assert result["heuristic_score"] > 0
    assert result["risk_score"] == result["heuristic_score"]
    assert result["category"] in {"Low", "Medium", "High"}
    assert any(reason["key"] == "model-unavailable" for reason in result["reasons"])
    assert "does not mean a URL is safe" in result["disclaimer"]


def test_model_prediction_is_reported_separately_from_heuristics(tmp_path):
    class FakeModel:
        classes_ = [0, 1]

        def predict_proba(self, _rows):
            return [[0.2, 0.8]]

    detector = URLDetector(tmp_path / "not-loaded.joblib")
    detector.model = FakeModel()
    result = detector.analyze("https://example.test/")
    assert result["model_available"] is True
    assert result["model_score"] == 80
    assert result["risk_score"] == round(0.7 * 80 + 0.3 * result["heuristic_score"])
    assert result["reasons"][0]["key"] == "model-estimate"
