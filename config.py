import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("PHISHINGRISK_SECRET_KEY")
    MAX_CONTENT_LENGTH = 16 * 1024
    DATABASE_PATH = Path(os.environ.get("PHISHINGRISK_DATABASE", BASE_DIR / "data" / "scans.db"))
    MODEL_PATH = Path(os.environ.get("PHISHINGRISK_MODEL", BASE_DIR / "models" / "url_model.joblib"))
