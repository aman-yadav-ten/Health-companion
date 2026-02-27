"""Application entrypoint for Health Companion."""

import os

from health_app import app


if __name__ == '__main__':
    debug_enabled = str(os.getenv('FLASK_DEBUG', '0')).lower() in ('1', 'true', 'yes')
    app.run(
        host=os.getenv('FLASK_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_PORT', '5001')),
        debug=debug_enabled,
    )
