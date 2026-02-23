"""
CORTEX - Backend Security System
Main application entry point.
"""

from flask import Flask


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    # TODO: Load config, register blueprints, init extensions
    return app


def run_app():
    """Run the application."""
    app = create_app()
    app.run()


if __name__ == "__main__":
    run_app()
