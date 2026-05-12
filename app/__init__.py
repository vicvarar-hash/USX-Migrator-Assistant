"""Flask application factory."""
from flask import Flask


def create_app():
    app = Flask(
        __name__,
        static_folder="../static",
        template_folder="templates",
    )
    app.secret_key = "usx-migrator-local-only"

    from .routes import bp
    app.register_blueprint(bp)

    return app
