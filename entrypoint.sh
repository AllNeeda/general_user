#!/bin/sh

python manage.py makemigrations
python manage.py migrate --noinput
python manage.py collectstatic --noinput

# Use Django's built-in autoreloader (watchdog) for development
if [ "$DJANGO_ENV" = "development" ] || [ "$ENV" = "development" ] || [ "$AUTO_RELOAD" = "true" ]; then
    # Start Django's development server with autoreload (default)
    # This automatically watches for file changes and reloads
    exec python manage.py runserver 0.0.0.0:8000
else
    # In production, check if we should use gunicorn with reload
    # This allows auto-reload in production-like environments
    if [ "$GUNICORN_RELOAD" = "true" ]; then
        # Use gunicorn with --reload flag to watch for file changes
        exec gunicorn app.wsgi:application --bind 0.0.0.0:8000 --reload
    else
        # In production, execute the normal entrypoint command (e.g., gunicorn without reload)
        exec "$@"
    fi
fi
