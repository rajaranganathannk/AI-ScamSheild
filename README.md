# PhishingRisk AI

PhishingRisk AI is a local Flask web application that inspects URL structure for common phishing indicators. It does **not** visit URLs, fetch website content, or send submitted links to an external service. The app can optionally load a locally trained supervised scikit-learn model. Until you provide a legitimate labeled dataset and train that model, it clearly operates in **heuristic-only** mode.

> A score is only an estimate. A low score does not prove a URL is safe, and a high score does not prove it is malicious. Do not use this app as the only basis for a security decision.

## What it includes

- Responsive dark dashboard with URL scanning, risk score, category, explanation, activity statistics, and local history.
- URL parser and numeric feature extractor that rejects malformed, non-HTTP(S), empty, and overlong input.
- Explainable heuristic indicators and an explicit model-unavailable fallback.
- Optional `DictVectorizer` + `RandomForestClassifier` scikit-learn pipeline, trained only from a real user-supplied labeled CSV.
- SQLite scan history using parameterized SQL.
- Pytest coverage for URL edge cases, fallback mode, storage, and Flask routes.

## Architecture

- `app.py` creates the Flask app and exposes `/`, `/api/scan`, and `/api/history`.
- `src/url_features.py` validates URLs and extracts reusable numeric features without network access.
- `src/detector.py` combines an optional trained model estimate and independent heuristic score.
- `src/database.py` creates and accesses the local SQLite database.
- `scripts/train_model.py` trains and saves a model; `scripts/evaluate_model.py` evaluates its held-out split.
- `templates/` and `static/` provide the browser interface. User-submitted text is rendered with `textContent`, not HTML interpolation.

Flask serves only the template and static assets; the database and model directories have no public routes. SQLite database files and trained model files are ignored by Git. URL credentials, fragments, and common sensitive query parameter values (for example `token`, `password`, and `api_key`) are redacted before a scan is saved to history.

## Requirements and Python 3.14

Python 3.14.8 is suitable for the app. Flask supports Python 3.14, and current scikit-learn releases (1.7.2 and newer) provide Python 3.14-compatible releases/wheels. This project requires `scikit-learn>=1.7.2`; it does not pin an older version lacking Python 3.14 support. Model training and evaluation need that dependency. The Flask application itself has an explicit fallback if no model file exists (and remains usable without scikit-learn installed).

## Windows PowerShell setup

Run these commands from the project directory in the VS Code terminal:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use this for the current terminal only, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

No API key or external service is needed. Flask starts on `http://127.0.0.1:5000` and debug mode is disabled by default.

## Labeled dataset and model training

No training dataset is bundled, and no training metrics are claimed. Obtain a lawful, appropriately licensed dataset from a reputable source, for example:

- [PhishTank developer information](https://phishtank.org/developer_info.php) — phishing URL data and usage details.
- [OpenPhish](https://openphish.com/) — phishing intelligence feed and terms.
- [Tranco](https://tranco-list.eu/) — popular-domain list that may support a benign class, subject to its terms.

Use the dataset provider's instructions and license, and avoid collecting or publishing URLs containing real credentials, personal tokens, or other sensitive values. To form a binary classification dataset, prepare a UTF-8 CSV at `data/labeled_urls.csv` with columns `url,label`. Each URL must be a complete `http://` or `https://` URL. Labels may be `1` / `phishing` / `malicious` or `0` / `benign` / `legitimate` / `legit`. Include at least 10 unique URLs and multiple examples from both classes; the script requires at least two of each. Remove duplicate URLs and inspect class balance and collection dates before training.

```csv
url,label
https://sample-from-your-dataset.example/path,phishing
https://another-sample-from-your-dataset.example,benign
```

The rows above show the **format only**, not training data. Do not use placeholders as a real dataset. The training script normalizes/validates input features, deduplicates URLs, and uses a reproducible five-fold stratified split grouped by hostname (seed `42` by default) so URLs from one host do not occur in both training and test rows. Each label must occur on at least five distinct hostnames. The pipeline is fitted on training hosts only and writes `models/url_model.joblib`. The same held-out split is recreated by the evaluation script:

```powershell
python scripts/train_model.py --data data/labeled_urls.csv
python scripts/evaluate_model.py --data data/labeled_urls.csv
```

Evaluation reports accuracy, precision, recall, F1-score, confusion matrix, and false-positive rate. Metrics reflect only the supplied dataset and split; they do not establish real-world detection performance. Retrain and evaluate after changing the dataset or feature extraction logic. Only load model files you trained or trust: joblib/pickle artifacts can execute code when loaded.

## Start the application

```powershell
python app.py
```

Open `http://127.0.0.1:5000` in your browser. The URL analyzer only parses the submitted string and computes features locally; it never resolves DNS or opens the site. Scan records are stored in `data/scans.db`. The clear-history control asks for confirmation before deleting records.

Optional environment settings:

```powershell
$env:PHISHINGRISK_DATABASE = "C:\path\to\scans.db"
$env:PHISHINGRISK_MODEL = "C:\path\to\url_model.joblib"
python app.py
```

The host defaults to loopback (`127.0.0.1`), making it available only on the local machine. Do not expose the development server directly to the internet. Set a unique `PHISHINGRISK_SECRET_KEY` if adding Flask features that rely on sessions.

## Run tests

```powershell
python -m pytest -q
```

Tests use reserved documentation domains and synthetic inputs; they do not contact any website.

## Limitations and future work

- Heuristic signals are simple and can miss novel phishing techniques or flag benign URLs.
- Supervised-model quality depends on dataset licensing, freshness, class balance, labeling quality, and representative evaluation. Dataset shift can make metrics misleading.
- Model output is a ranking estimate, not a calibrated probability of compromise.
- URL features are not a substitute for DNS, certificate, page-content, or reputation checks. No such checks are made here.
- History is local to the configured SQLite file and is not encrypted. Avoid scanning URLs that contain secrets or personal tokens.
- A future reputation API integration should be opt-in, explain what data is sent, and obtain consent before transmitting a URL.
