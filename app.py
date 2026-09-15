import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import config
from routes import register_blueprints


def create_app(config_name='default'):
    """Application factory for NetIntel NOC Network Traffic Analysis Platform."""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Ensure required directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)

    # Configure Logging
    configure_logging(app)
    app.logger.info("Starting NetIntel NOC Network Traffic Analysis Platform...")

    # Register Blueprints
    register_blueprints(app)

    # Register Error Handlers
    register_error_handlers(app)

    return app


def configure_logging(app):
    """Sets up application logging."""
    log_file = os.path.join(app.config['LOG_DIR'], 'netintel_noc.log')

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )

    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))

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
        app.logger.warning("413 Error: File upload exceeded MAX_CONTENT_LENGTH.")
        return jsonify({
            "error": "File too large (exceeds 32MB limit)",
            "status_code": 413
        }), 413


# Create app instance for WSGI
app = create_app(os.environ.get("FLASK_ENV", "development"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=app.config["DEBUG"]
    )