"""Evaluate a saved URL classifier on a held-out stratified dataset split."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.train_model import load_dataset, split_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "labeled_urls.csv")
    parser.add_argument("--model", type=Path, default=ROOT / "models" / "url_model.joblib")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        import joblib
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            f1_score,
            precision_score,
            recall_score,
        )
        features, labels, groups = load_dataset(args.data)
        _train_indices, test_indices = split_dataset(features, labels, groups, args.seed)
        x_test = [features[index] for index in test_indices]
        y_test = [labels[index] for index in test_indices]
        model = joblib.load(args.model)
    except (ImportError, OSError, ValueError) as exc:
        raise SystemExit(f"Could not evaluate model: {exc}") from exc

    predictions = model.predict(x_test)
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall: {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1-score: {f1_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Confusion matrix [ [TN, FP], [FN, TP] ]: [[{tn}, {fp}], [{fn}, {tp}]]")
    print(f"False-positive rate: {false_positive_rate:.4f}")


if __name__ == "__main__":
    main()
