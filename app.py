import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, send_from_directory
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import config
from routes import register_blueprints


# =========================================================
# APPLICATION FACTORY
# =========================================================

def create_app(config_name="default"):
    """Application factory for NetIntel NOC."""

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # React production build directory
    frontend_dist = os.path.join(
        base_dir,
        "frontend",
        "dist"
    )

    # Create Flask application
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Create required directories
    os.makedirs(
        app.config["UPLOAD_FOLDER"],
        exist_ok=True
    )

    os.makedirs(
        app.config["LOG_DIR"],
        exist_ok=True
    )

    # Configure logging
    configure_logging(app)

    app.logger.info(
        "Starting NetIntel NOC Network Traffic Analysis Platform..."
    )

    # =====================================================
    # REGISTER API ROUTES
    # =====================================================

    register_blueprints(app)

    # =====================================================
    # SERVE REACT FRONTEND
    # =====================================================

    @app.route("/")
    def index():
        """
        Serve React application's index.html.
        """

        index_file = os.path.join(
            frontend_dist,
            "index.html"
        )

        if os.path.isfile(index_file):
            return send_from_directory(
                frontend_dist,
                "index.html"
            )

        app.logger.error(
            "React frontend not found: %s",
            index_file
        )

        return jsonify({
            "error": "Frontend build not found",
            "message": "React production build is missing."
        }), 404

    @app.route("/<path:path>")
    def frontend_routes(path):
        """
        Serve React static files and support
        React client-side routing.
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

        first_part = path.split("/")[0]

        # Do not intercept API routes
        if first_part in api_prefixes:
            return jsonify({
                "error": "Resource not found",
                "status_code": 404
            }), 404

        # Requested React static file
        requested_file = os.path.join(
            frontend_dist,
            path
        )

        if os.path.isfile(requested_file):
            return send_from_directory(
                frontend_dist,
                path
            )

        # React SPA fallback
        index_file = os.path.join(
            frontend_dist,
            "index.html"
        )

        if os.path.isfile(index_file):
            return send_from_directory(
                frontend_dist,
                "index.html"
            )

        app.logger.error(
            "React frontend build missing: %s",
            index_file
        )

        return jsonify({
            "error": "Frontend build not found",
            "status_code": 404
        }), 404

    # Register error handlers
    register_error_handlers(app)

    return app


# =========================================================
# LOGGING
# =========================================================

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


# =========================================================
# ERROR HANDLERS
# =========================================================

def register_error_handlers(app):

    @app.errorhandler(404)
    def not_found_error(error):

        app.logger.warning(
            "404 Error: %s",
            error
        )

        return jsonify({
            "error": "Resource not found",
            "status_code": 404
        }), 404

    @app.errorhandler(500)
    def internal_error(error):

        app.logger.error(
            "500 Error: %s",
            error
        )

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


# =========================================================
# WSGI APPLICATION
# =========================================================

app = create_app(
    os.environ.get(
        "FLASK_ENV",
        "development"
    )
)


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=app.config["DEBUG"]
    )