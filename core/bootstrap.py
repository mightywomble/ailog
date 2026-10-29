"""Process startup / shutdown, kept out of the route module.

``main()`` is what ``python app.py`` runs: initialise app settings, start the
scheduler and background samplers, then serve.  Keeping it here means ``app.py``
is a route module plus a three-line entry point, and a future WSGI entry point
(gunicorn) can call :func:`start_background_services` with its own module
reference instead of relying on ``__main__`` behaviour.
"""

from __future__ import annotations

import atexit
import os


def start_background_services(app, app_module) -> None:
    """Start schedulers and samplers for *app* (the module that owns them)."""
    app_module.initialize_app()

    scheduler = getattr(app_module, 'scheduler', None)
    if scheduler is not None:
        scheduler.start()
        app_module.startup_scheduler()
        atexit.register(scheduler.shutdown)

    # Docker history sampler: keeps a rolling in-memory window per Docker host
    # so the /docker/<host_key> charts survive a page reload.
    try:
        from dockermon import history as docker_history
        docker_history.start_sampler(app)
        atexit.register(docker_history.stop_sampler)
    except Exception:
        app.logger.exception('could not start the docker history sampler')


def main(app, app_module) -> None:
    start_background_services(app, app_module)
    app.run(
        host=os.getenv('AILOG_BIND', '127.0.0.1'),
        port=int(os.getenv('AILOG_PORT', '5001')),
        debug=False,
    )
