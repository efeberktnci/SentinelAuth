"""
SentinelAuth entry point.

Run locally:
    pip install -r requirements.txt
    python run.py
"""
import os

from flask import Flask, render_template

from api.routes import api
from lab.routes import lab


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "ui", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "ui", "static"),
    )
    app.secret_key = os.environ.get("FLASK_SECRET", "sentinel_dev_secret_change_in_prod")
    app.register_blueprint(api)
    app.register_blueprint(lab)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n  SentinelAuth -- Local Identity Integrity Lab")
    print("  http://127.0.0.1:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
