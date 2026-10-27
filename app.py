import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config
from src.database import clear_scans, get_scans, get_statistics, initialize_database, save_scan
from src.detector import URLDetector
from src.url_features import URLValidationError


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    initialize_database(app.config["DATABASE_PATH"])
    detector = URLDetector(app.config["MODEL_PATH"])
    app.extensions["url_detector"] = detector
    if detector.model_error:
        app.logger.warning("%s; continuing in heuristic-only mode.", detector.model_error)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            model_available=app.extensions["url_detector"].model_available,
        )

    @app.post("/api/scan")
    def scan():
        if not request.is_json:
            return jsonify(error="Send a JSON body containing a url field."), 400
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="The request body must be a JSON object."), 400
        try:
            result = app.extensions["url_detector"].analyze(payload.get("url"))
        except URLValidationError as exc:
            return jsonify(error=str(exc)), 400
        result["scan_id"] = save_scan(app.config["DATABASE_PATH"], result)
        return jsonify(result)

    @app.get("/api/history")
    def history():
        return jsonify(scans=get_scans(app.config["DATABASE_PATH"]), statistics=get_statistics(app.config["DATABASE_PATH"]))

    @app.delete("/api/history")
    def delete_history():
        clear_scans(app.config["DATABASE_PATH"])
        return jsonify(message="Scan history cleared.")

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify(error="Request is too large."), 413

    @app.errorhandler(500)
    def internal_error(_error):
        app.logger.exception("Unhandled application error")
        return jsonify(error="An unexpected error occurred. Please try again."), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("PHISHINGRISK_HOST", "127.0.0.1"),
        port=int(os.environ.get("PHISHINGRISK_PORT", "5000")),
        debug=False,
    )
