"""HTTP and WebSocket API for EasyShark daemon mode."""

from .server import app, create_app

__all__ = ["app", "create_app"]
