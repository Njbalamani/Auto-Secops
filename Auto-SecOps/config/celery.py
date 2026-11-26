import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("autosecops")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
app.conf.imports = ["config.maintenance"]

app.conf.beat_schedule = {
    "autosecops-scheduled-maintenance": {
        "task": "config.maintenance.run_scheduled_maintenance",
        "schedule": 3600.0,
        "options": {"expires": 3000},
    }
}
