"""Combines optional supervised predictions with transparent heuristic signals."""

from pathlib import Path
import pickle

from src.url_features import extract_features, explain_heuristics, normalize_url


class URLDetector:
    def __init__(self, model_path: str | Path):
        self.model = None
        self.model_error: str | None = None
        path = Path(model_path)
        if path.exists():
            try:
                import joblib

                self.model = joblib.load(path)
            except (ImportError, OSError, ValueError, EOFError, pickle.UnpicklingError, AttributeError, TypeError) as exc:
                self.model_error = f"Saved model could not be loaded: {exc}"

    @property
    def model_available(self) -> bool:
        return self.model is not None

    @staticmethod
    def _heuristic_score(features: dict[str, float]) -> int:
        points = (
            (features["is_ip_address"], 25),
            (1 - features["uses_https"], 8),
            (features["has_at_symbol"], 20),
            (features["has_credentials"], 15),
            (features["is_shortened"], 12),
            (features["has_punycode"] or features["has_non_ascii_hostname"], 15),
            (features["suspicious_character_count"] > 0, 10),
            (features["hostname_label_count"] >= 5, 10),
            (features["hyphen_count"] >= 3, 8),
            (features["suspicious_keyword_count"] > 0, 8),
            (features["url_length"] >= 120, 8),
            (features["query_parameter_count"] >= 5, 5),
        )
        return min(100, sum(weight for condition, weight in points if condition))

    def analyze(self, url: str) -> dict:
        normalized = normalize_url(url)
        features = extract_features(normalized)
        heuristic_score = self._heuristic_score(features)
        evidence = explain_heuristics(normalized)

        model_score = None
        if self.model is not None:
            row = [features]
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(row)[0]
                classes = list(self.model.classes_)
                phishing_index = next(
                    (i for i, label in enumerate(classes) if str(label).lower() in {"1", "phishing", "malicious"}),
                    None,
                )
                if phishing_index is not None:
                    model_score = round(float(probabilities[phishing_index]) * 100)
            if model_score is None:
                prediction = str(self.model.predict(row)[0]).lower()
                model_score = 80 if prediction in {"1", "phishing", "malicious"} else 20

        score = heuristic_score if model_score is None else round(0.7 * model_score + 0.3 * heuristic_score)
        category = "Low" if score <= 33 else "Medium" if score <= 66 else "High"
        if self.model_available:
            evidence.insert(
                0,
                {
                    "key": "model-estimate",
                    "message": f"The trained classifier estimated a {model_score}/100 phishing score. This is a model estimate, not a calibrated probability of compromise.",
                    "severity": "model",
                },
            )
        else:
            evidence.insert(
                0,
                {
                    "key": "model-unavailable",
                    "message": "No trained model is available. This score uses transparent heuristic rules only.",
                    "severity": "info",
                },
            )
        return {
            "url": normalized,
            "risk_score": score,
            "category": category,
            "model_available": self.model_available,
            "model_score": model_score,
            "heuristic_score": heuristic_score,
            "reasons": evidence,
            "disclaimer": "This estimate can be wrong. A low score does not mean a URL is safe. The URL was not visited or sent to a third party.",
        }
