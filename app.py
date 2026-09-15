import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, send_from_directory
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import config
from routes import register_blueprints


def create_app(config_name="default"):
    """Application factory for NetIntel NOC Network Traffic Analysis Platform."""

    # React production build directory
    frontend_dist = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "frontend",
        "dist"
    )

    # Create Flask application
    app = Flask(
        __name__,
        static_folder=frontend_dist,
        static_url_path=""
    )

    # Load configuration
    app.config.from_object(config[config_name])

    # Ensure required directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["LOG_DIR"], exist_ok=True)

    # Configure logging
    configure_logging(app)

    app.logger.info(
        "Starting NetIntel NOC Network Traffic Analysis Platform..."
    )

    # Register API blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # ---------------------------------------------------------
    # Serve React frontend
    # ---------------------------------------------------------

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        """
        Serve the React frontend.

        API routes are handled by Flask blueprints.
        Non-API routes are served from the React production build.
        """

        # API route prefixes
        api_prefixes = (
            "upload",
            "analyze",
            "export",
            "model",
            "history",
            "health",
            "api"
        )

        # Do not allow the React catch-all route to intercept API routes
        if path and path.split("/")[0] in api_prefixes:
            return jsonify({
                "error": "Resource not found",
                "status_code": 404
            }), 404

        # Requested static file
        requested_file = os.path.join(frontend_dist, path)

        if path and os.path.isfile(requested_file):
            return send_from_directory(frontend_dist, path)

        # React SPA fallback
        # This allows React Router/client-side routes to work.
        index_file = os.path.join(frontend_dist, "index.html")

        if os.path.isfile(index_file):
            return send_from_directory(frontend_dist, "index.html")

        # Frontend build does not exist
        return jsonify({
            "error": "Frontend build not found",
            "message": "The React frontend has not been built yet.",
            "status_code": 404
        }), 404

    return app


def configure_logging(app):
    """Sets up application logging."""

    log_file = os.path.join(
        app.config["LOG_DIR"],
        "netintel_noc.log"
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )

    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s "
            "[in %(pathname)s:%(lineno)d]"
        )
    )

    file_handler.setLevel(
        logging.INFO if not app.debug else logging.DEBUG
    )

    app.logger.addHandler(file_handler)

    app.logger.setLevel(
        logging.INFO if not app.debug else logging.DEBUG
    )


def register_error_handlers(app):
    """Registers global error handlers."""

    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.warning(f"404 Error: {error}")

        return jsonify({
            "error": "Resource not found",
            "status_code": 404
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"500 Error: {error}")

        return jsonify({
            "error": "Internal server error",
            "status_code": 500
        }), 500

    @app.errorhandler(413)
    def request_entity_too_large(error):
        app.logger.warning(
            "413 Error: File upload exceeded MAX_CONTENT_LENGTH."
        )

        return jsonify({
            "error": "File too large (exceeds 32MB limit)",
            "status_code": 413
        }), 413


# Create app instance for WSGI / Gunicorn
app = create_app(
    os.environ.get("FLASK_ENV", "development")
)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=app.config["DEBUG"]
    )