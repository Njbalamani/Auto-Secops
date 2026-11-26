import os

bind = os.getenv("GUNICORN_BIND", "0.0.0.0:8000")
workers = int(os.getenv("WEB_CONCURRENCY", "3"))
worker_class = "gthread"
threads = int(os.getenv("WEB_THREADS", "4"))
timeout = int(os.getenv("WEB_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
