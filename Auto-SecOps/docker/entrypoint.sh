#!/bin/sh
set -e

python manage.py migrate --noinput

if [ "${AUTOSEOPS_SEED_ON_START:-False}" = "True" ]; then
  python manage.py seed_autosecops
  python manage.py seed_detections
  python manage.py seed_assets
fi

if [ "$1" = "web" ]; then
  python manage.py collectstatic --noinput
  if [ "${DJANGO_SETTINGS_MODULE:-config.settings}" = "config.settings_prod" ]; then
    exec gunicorn config.wsgi:application --config gunicorn.conf.py
  fi
  exec python manage.py runserver 0.0.0.0:8000
elif [ "$1" = "worker" ]; then
  exec celery -A config worker -l info
elif [ "$1" = "beat" ]; then
  exec celery -A config beat -l info
else
  exec "$@"
fi
