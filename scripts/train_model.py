"""Train a URL classifier from a user-provided, labeled CSV dataset."""

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from urllib.parse import urlsplit

from src.url_features import URLValidationError, extract_features, normalize_url


def load_dataset(path: Path) -> tuple[list[dict[str, float]], list[int], list[str]]:
    features = []
    labels = []
    groups = []
    seen_urls: dict[str, int] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
            raise ValueError("CSV must contain columns named url and label.")
        for line_number, row in enumerate(reader, start=2):
            label_value = (row.get("label") or "").strip().lower()
            if label_value in {"1", "phishing", "malicious"}:
                label = 1
            elif label_value in {"0", "benign", "legitimate", "legit"}:
                label = 0
            else:
                raise ValueError(f"Unsupported label on CSV line {line_number}; use 0/1 or benign/phishing.")
            try:
                url = normalize_url(row.get("url") or "")
                url_features = extract_features(url)
            except URLValidationError as exc:
                raise ValueError(f"Invalid URL on CSV line {line_number}: {exc}") from exc
            if url in seen_urls:
                if seen_urls[url] != label:
                    raise ValueError(f"Conflicting labels for duplicate URL on CSV line {line_number}.")
                continue
            seen_urls[url] = label
            features.append(url_features)
            labels.append(label)
            groups.append((urlsplit(url).hostname or "").lower())
    if len(set(labels)) != 2:
        raise ValueError("Dataset must include at least one benign and one phishing URL.")
    if min(labels.count(0), labels.count(1)) < 2:
        raise ValueError("Each label needs at least two rows for a stratified train/test split.")
    for label in (0, 1):
        label_groups = {group for group, row_label in zip(groups, labels) if row_label == label}
        if len(label_groups) < 5:
            raise ValueError(
                "Each label needs at least five distinct hostnames for a 5-fold, hostname-grouped split."
            )
    return features, labels, groups


def split_dataset(features, labels, groups, seed):
    from sklearn.model_selection import StratifiedGroupKFold

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    for train_indices, test_indices in splitter.split(features, labels, groups):
        if len({labels[index] for index in test_indices}) == 2:
            return train_indices, test_indices
    raise ValueError("Could not create a grouped test split containing both classes; add more labeled hostnames.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "labeled_urls.csv")
    parser.add_argument("--model", type=Path, default=ROOT / "models" / "url_model.joblib")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.pipeline import Pipeline
        import joblib
    except ImportError as exc:
        raise SystemExit(
            "Model training requires scikit-learn. Install project dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    try:
        features, labels, groups = load_dataset(args.data)
        train_indices, test_indices = split_dataset(features, labels, groups, args.seed)
        x_train = [features[index] for index in train_indices]
        y_train = [labels[index] for index in train_indices]
        x_test = [features[index] for index in test_indices]
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    model = Pipeline(
        [
            ("vectorizer", DictVectorizer()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced",
                    random_state=args.seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model)
    print(f"Trained model saved to {args.model}")
    print(f"Training rows: {len(x_train)}; held-out rows: {len(x_test)}; random seed: {args.seed}")
    print("Run python scripts/evaluate_model.py to calculate held-out metrics.")


if __name__ == "__main__":
    main()
